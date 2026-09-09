"""
Alby Hub manager — shared backend for Lightning Wallet Connections API and recovery CLI.

Interfaces with the local Alby Hub instance at
http://127.0.0.1:18080 by default (override with NWC_ALBY_HUB_API_BASE).
All sensitive values (passwords, bearer tokens, pairing URIs, macaroon
contents, Nostr private keys) are redacted from any exception messages
or log output.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import nwc_audit as _audit_mod

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────

DEFAULT_API_BASE = os.environ.get(
    "NWC_ALBY_HUB_API_BASE",
    "http://127.0.0.1:18080",
)
DEFAULT_UNLOCK_PASSWORD_FILE = os.environ.get(
    "NWC_UNLOCK_PASSWORD_FILE", "/var/lib/albyhub/unlock-password"
)
DEFAULT_MACAROON_FILE = os.environ.get(
    "NWC_LND_MACAROON_FILE", "/run/lnd/albyhub.macaroon"
)
DEFAULT_LND_ADDRESS = os.environ.get("NWC_LND_ADDRESS", "127.0.0.1:10009")
DEFAULT_LND_CERT_FILE = os.environ.get("NWC_LND_CERT_FILE", "/var/lib/lnd/tls.cert")
DEFAULT_LND_SOCKET = "/run/lnd/lnd.socket"

LNURL_DESCRIPTION_DEFAULT = "Pay via Lightning"
NWC_MIN_SENDABLE_MSAT = 1000
NWC_MAX_SENDABLE_MSAT = 1_000_000_000

# Metadata key used to mark managed isolated wallets
_MANAGED_APP_STORE_ID = "uncle-jim"
_MANAGED_META_KEY = "app_store_app_id"

RECEIVE_ONLY_SCOPES = [
    "get_info",
    "get_balance",
    "make_invoice",
    "lookup_invoice",
    "list_transactions",
    "notifications",
]

LIMITED_SEND_SCOPES = RECEIVE_ONLY_SCOPES + ["pay_invoice"]

# ── Exceptions ─────────────────────────────────────────────────────


class AlbyHubError(Exception):
    """Base error from the Alby Hub manager.

    The message string is safe to surface to the user — it never
    contains raw secret material.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code

    def __str__(self) -> str:
        return f"[{self.code}] {self.args[0]}"


class AlbyHubHttpError(AlbyHubError):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"http_{status_code}", message)
        self.status_code = status_code


# ── Manager class ──────────────────────────────────────────────────


class AlbyHubManager:
    """Thread-safe manager for Alby Hub API operations."""

    def __init__(
        self,
        api_base: str = DEFAULT_API_BASE,
        unlock_password_file: str = DEFAULT_UNLOCK_PASSWORD_FILE,
        macaroon_file: str = DEFAULT_MACAROON_FILE,
        lnd_address: str = DEFAULT_LND_ADDRESS,
        lnd_cert_file: str = DEFAULT_LND_CERT_FILE,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.unlock_password_file = unlock_password_file
        self.macaroon_file = macaroon_file
        self.lnd_address = lnd_address
        self.lnd_cert_file = lnd_cert_file
        self._lock = threading.Lock()
        self._token: str | None = None

    # ── Low-level HTTP ─────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        token: str | None = None,
        timeout: int = 30,
    ) -> dict:
        """Make a raw HTTP request to the local Alby Hub API.

        Returns the parsed JSON response body.
        Raises AlbyHubHttpError on non-2xx responses.
        Secrets in response bodies are never included in raised exceptions.
        """
        url = f"{self.api_base}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            code = exc.code
            # Read and discard the body — we do NOT include it in the exception
            try:
                exc.read()
            except Exception:
                pass
            raise AlbyHubHttpError(code, f"Hub API {method} {path} returned HTTP {code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise AlbyHubError(
                "hub_unreachable",
                f"Hub API {method} {path} is unreachable",
            ) from None

    def _authenticated_request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        timeout: int = 30,
    ) -> dict:
        """Make an authenticated request; retry once with a fresh token on 401/403."""
        token = self.ensure_ready()
        try:
            return self._request(method, path, body=body, token=token, timeout=timeout)
        except AlbyHubHttpError as exc:
            if exc.status_code in (401, 403):
                with self._lock:
                    self._token = None
                token = self.ensure_ready()
                return self._request(method, path, body=body, token=token, timeout=timeout)
            raise

    def _paginate(self, path_template: str, page_size: int = 100) -> list[dict]:
        """Paginate a list API completely, collecting all items.

        ``path_template`` must contain ``{limit}`` and ``{offset}`` placeholders.
        """
        token = self.ensure_ready()
        offset = 0
        results: list[dict] = []
        while True:
            path = path_template.format(limit=page_size, offset=offset)
            page = self._request("GET", path, token=token)
            # Alby Hub returns apps at the top level or under "apps"/"transactions"
            total_count: int | None = None
            if isinstance(page, list):
                items = page
            elif isinstance(page, dict):
                items = page.get("apps") or page.get("transactions") or []
                if page.get("totalCount") is not None:
                    total_count = int(page.get("totalCount"))
            else:
                items = []
            if not isinstance(items, list):
                break
            results.extend(items)
            if total_count is not None:
                if len(results) >= total_count:
                    break
            elif len(items) < page_size:
                break
            offset += page_size
        return results

    # ── Audit log helper ───────────────────────────────────────────

    def _audit(self, event: str, **fields: Any) -> None:
        """Emit structured audit log entry."""
        _audit_mod.audit_log(event, **fields)

    # ── Startup / Auth ─────────────────────────────────────────────

    def _read_unlock_password(self) -> str:
        try:
            with open(self.unlock_password_file, "r") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise AlbyHubError(
                "unlock_password_unavailable",
                "Cannot read Alby Hub unlock password",
            ) from exc

    def _wait_for_file(self, path: str, timeout: int = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.exists(path):
                return
            time.sleep(2)
        raise AlbyHubError(
            "dependency_unavailable",
            f"Timed out waiting for required file: {path}",
        )

    def _wait_for_hub_api(self, timeout: int = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._request("GET", "/api/info", timeout=5)
                return
            except AlbyHubError:
                pass
            time.sleep(3)
        raise AlbyHubError("hub_unavailable", "Timed out waiting for Alby Hub API")

    def _hub_setup(self, password: str) -> None:
        """Perform /api/setup idempotently."""
        try:
            info = self._request("GET", "/api/info", timeout=10)
            if info.get("setupCompleted"):
                return
        except AlbyHubError:
            pass

        setup_body = {
            "backendType": "LND",
            "unlockPassword": password,
            "lndAddress": self.lnd_address,
            "lndCertFile": self.lnd_cert_file,
            "lndMacaroonFile": self.macaroon_file,
        }
        try:
            self._request("POST", "/api/setup", body=setup_body, timeout=30)
        except AlbyHubHttpError as exc:
            if exc.status_code == 409:
                return  # already setup
            raise

    def _obtain_token(self, password: str) -> str:
        # NOTE (security): Alby Hub unlock tokens are binary ("full" | "read"),
        # so a receive-only service still requires a *full* token to mint
        # invoices (POST /api/invoices with toAppId). This credential grants
        # full hub admin over every managed wallet, so any caller of this
        # manager (e.g. the nwc-lnurl unit) MUST stay loopback-only and run
        # under the strict systemd sandbox (see modules/lnurl.nix).
        info = self._request("GET", "/api/info", timeout=10)
        if info.get("running"):
            resp = self._request(
                "POST",
                "/api/unlock",
                body={
                    "unlockPassword": password,
                    "permission": "full",
                },
                timeout=30,
            )
        else:
            resp = self._request(
                "POST",
                "/api/start",
                body={"unlockPassword": password},
                timeout=30,
            )
        token = (
            resp.get("token")
            or resp.get("accessToken")
            or resp.get("access_token")
        )
        if not token or not isinstance(token, str):
            raise AlbyHubError("auth_failed", "Alby Hub auth response missing token")
        return token

    def _wait_for_node_ready(self, token: str, timeout: int = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                status = self._request(
                    "GET", "/api/node/status", token=token, timeout=10
                )
                if status.get("isReady") or status.get("running") or status.get("online"):
                    return
            except AlbyHubError:
                pass
            time.sleep(3)
        raise AlbyHubError("node_not_ready", "Timed out waiting for Alby Hub node to be ready")

    def ensure_ready(self) -> str:
        """Ensure Alby Hub is set up, unlocked, and authenticated.

        Returns a valid bearer token.  Caches it and uses a lock to
        prevent concurrent setup races.
        """
        with self._lock:
            if self._token:
                return self._token

            password = self._read_unlock_password()
            self._wait_for_file(self.macaroon_file, timeout=120)
            self._wait_for_hub_api(timeout=120)
            self._hub_setup(password)
            token = self._obtain_token(password)
            self._wait_for_node_ready(token, timeout=120)
            self._token = token
            return token

    # ── App isolation helpers ──────────────────────────────────────

    @staticmethod
    def _parse_metadata(raw: Any) -> dict:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            try:
                result = json.loads(raw)
                if isinstance(result, dict):
                    return result
            except Exception:
                pass
        return {}

    def _is_managed_app(self, app: dict) -> bool:
        meta = self._parse_metadata(app.get("metadata"))
        alias = str(meta.get("lnurl_alias", "")).strip().lower()
        return (
            meta.get(_MANAGED_META_KEY) == _MANAGED_APP_STORE_ID
            and bool(alias)
        )

    def _app_to_wallet_meta(self, app: dict, domain: str | None) -> dict:
        meta = self._parse_metadata(app.get("metadata"))
        alias = meta.get("lnurl_alias", "")
        address = f"{alias}@{domain}" if alias and domain else None

        scopes = app.get("scopes") or []
        access_preset = (
            "send_receive_limited" if "pay_invoice" in scopes else "receive_only"
        )

        balance_msat = int(app.get("balanceMsat", 0) or 0)
        balance_sats = balance_msat // 1000
        dust_msat = balance_msat % 1000

        spending_limit_sats: int | None = None
        max_amount = app.get("maxAmountSat") or 0
        if max_amount:
            spending_limit_sats = int(max_amount)

        # Count pending transactions from the budget or transactions list
        pending_txs = int(app.get("pendingTransactionsCount", 0) or 0)

        return {
            "id": str(app.get("id", "")),
            "pubkey": app.get("appPubkey") or app.get("nostrPubkey") or app.get("pubkey") or "",
            "name": app.get("name", ""),
            "alias": alias,
            "lightning_address": address,
            "access_preset": access_preset,
            "spending_limit_sats": spending_limit_sats,
            "balance_sats": balance_sats,
            "dust_msat": dust_msat,
            "pending_transactions": pending_txs,
            "created_at": app.get("createdAt") or app.get("created_at"),
            "min_sendable_msat": int(
                meta.get("lnurl_min_sendable_msat", NWC_MIN_SENDABLE_MSAT)
            ),
            "max_sendable_msat": int(
                meta.get("lnurl_max_sendable_msat", NWC_MAX_SENDABLE_MSAT)
            ),
        }

    def _all_managed_apps(self) -> list[dict]:
        apps = self._paginate("/api/apps?limit={limit}&offset={offset}&order_by=created_at")
        return [a for a in apps if a.get("isolated") and self._is_managed_app(a)]

    @staticmethod
    def _app_pubkey(app: dict) -> str:
        return (
            app.get("appPubkey") or app.get("nostrPubkey") or app.get("pubkey") or ""
        )

    def _app_alias(self, app: dict) -> str:
        """Return the wallet's alias.

        The alias lives in the app's ``metadata.lnurl_alias`` — apps have no
        top-level ``alias`` field, so ``app.get("alias")`` is always empty.
        """
        meta = self._parse_metadata(app.get("metadata"))
        return str(meta.get("lnurl_alias", "") or "").strip()

    def _find_managed_app(self, identifier: str) -> dict | None:
        """Resolve a wallet by id, pubkey, name, alias or Lightning Address.

        ``nwc-wallet list`` prints ``name``, ``alias`` and ``lightning_address``
        for every wallet, and the CLI's ``delete``/``drain``/``rotate``
        subcommands take a single free-form ``<wallet>`` argument — so all of
        those identifiers must resolve here. Matching on only the numeric id
        and pubkey made every listed wallet "not found" when addressed by the
        name it was listed under.

        Matching is case- and whitespace-insensitive. Raises ``wallet_ambiguous``
        if more than one wallet matches on name/alias.
        """
        needle = str(identifier or "").strip().lower()
        if not needle:
            return None

        apps = self._all_managed_apps()

        # Unambiguous identifiers win outright.
        for app in apps:
            if str(app.get("id", "")).lower() == needle:
                return app
        for app in apps:
            if self._app_pubkey(app).lower() == needle:
                return app

        # Human-facing identifiers: wallet name, alias, or alias@domain.
        local_part = needle.split("@", 1)[0]
        matches: dict[str, dict] = {}
        for app in apps:
            name = str(app.get("name", "") or "").strip().lower()
            alias = self._app_alias(app).lower()
            if not name and not alias:
                continue
            if needle in (name, alias) or (local_part and local_part == alias):
                matches[str(app.get("id", ""))] = app

        if len(matches) > 1:
            raise AlbyHubError(
                "wallet_ambiguous",
                f"Multiple wallets match '{identifier.strip()}'. "
                "Re-run using the wallet id from 'nwc-wallet list'.",
            )
        if matches:
            return next(iter(matches.values()))
        return None

    # ── Public API ─────────────────────────────────────────────────

    def list_wallets(self, domain: str | None = None) -> list[dict]:
        """Return all managed isolated app wallets (no secrets)."""
        wallets = []
        for app in self._all_managed_apps():
            app_copy = dict(app)
            app_copy["pendingTransactionsCount"] = len(self._get_app_pending_txs(int(app["id"])))
            wallets.append(self._app_to_wallet_meta(app_copy, domain))
        return wallets

    def create_wallet(
        self,
        name: str,
        alias: str,
        access_preset: str,
        spending_limit_sats: int | None,
        domain: str | None = None,
    ) -> dict:
        """Create a new isolated Alby Hub app (wallet connection).

        Returns a dict containing:
          ``wallet``      — safe metadata (no secrets)
          ``pairing_uri`` — real Alby Hub pairingUri (returned ONCE)
          ``result``      — creation status report
        """
        # Validate uniqueness
        managed = self._all_managed_apps()
        for a in managed:
            meta = self._parse_metadata(a.get("metadata"))
            if meta.get("lnurl_alias", "").lower() == alias.lower():
                raise AlbyHubError(
                    "alias_exists", "That Lightning Address alias is already in use."
                )
            if (a.get("name") or "").lower() == name.lower():
                raise AlbyHubError(
                    "wallet_name_exists",
                    "That Wallet Connection name already exists.",
                )

        scopes = (
            LIMITED_SEND_SCOPES
            if access_preset == "send_receive_limited"
            else RECEIVE_ONLY_SCOPES
        )
        max_amount = (
            spending_limit_sats
            if access_preset == "send_receive_limited" and spending_limit_sats
            else 0
        )

        create_body: dict = {
            "name": name,
            "scopes": scopes,
            "isolated": True,
            "budgetRenewal": "never",
            "maxAmountSat": max_amount,
            "metadata": {
                _MANAGED_META_KEY: _MANAGED_APP_STORE_ID,
                "lnurl_alias": alias,
                "lnurl_description": LNURL_DESCRIPTION_DEFAULT,
                "lnurl_min_sendable_msat": NWC_MIN_SENDABLE_MSAT,
                "lnurl_max_sendable_msat": NWC_MAX_SENDABLE_MSAT,
            },
        }

        resp = self._authenticated_request("POST", "/api/apps", body=create_body)
        pairing_uri: str = resp.get("pairingUri") or resp.get("pairing_uri") or ""
        app_id = resp.get("id")

        # Fetch full app details for accurate metadata
        app_detail: dict | None = None
        if app_id is not None:
            try:
                app_detail = self._authenticated_request(
                    "GET", f"/api/v2/apps/{app_id}"
                )
            except AlbyHubError:
                pass

        if app_detail is None:
            # Fallback: search recent apps for the one we just created
            updated = self._all_managed_apps()
            for a in updated:
                if str(a.get("id", "")) == str(app_id):
                    app_detail = a
                    break

        wallet_meta = self._app_to_wallet_meta(app_detail or resp, domain)

        # Initial internal transfer for limited wallets
        funding_result: dict = {"attempted": False, "success": False}
        if (
            access_preset == "send_receive_limited"
            and spending_limit_sats
            and app_id is not None
        ):
            funding_result["attempted"] = True
            try:
                self._authenticated_request(
                    "POST",
                    "/api/transfers",
                    body={
                        "toAppId": int(app_id),
                        "amountSat": spending_limit_sats,
                        "description": f"Initial funding for {name}",
                    },
                )
                funding_result["success"] = True
            except AlbyHubError as exc:
                funding_result["error"] = exc.code
                funding_result["message"] = (
                    "The wallet was created successfully and the NWC connection secret is shown "
                    "above, but initial funding failed. Save the NWC secret now. "
                    "Do not recreate this wallet."
                )

        # Audit log: wallet created
        self._audit(
            "wallet_created",
            wallet_id=str(app_id) if app_id else "unknown",
            name=name,
            alias=alias,
            access_preset=access_preset,
            spending_limit_sats=spending_limit_sats,
            lightning_address=wallet_meta.get("lightning_address"),
            funding_attempted=funding_result["attempted"],
            funding_success=funding_result["success"],
        )

        return {
            "wallet": wallet_meta,
            "pairing_uri": pairing_uri,  # returned once on create only
            "result": {
                "wallet_created": True,
                "secret_created": bool(pairing_uri),
                "lightning_address_registered": bool(alias and domain),
                "funding": funding_result,
            },
        }

    def _get_app_balance_msat(self, app: dict) -> int:
        return int(app.get("balanceMsat", 0) or 0)

    def _get_app_pending_txs(self, app_id: int) -> list[dict]:
        txs = self._paginate(
            f"/api/transactions?appId={app_id}&limit={{limit}}&offset={{offset}}"
        )
        return [
            t for t in txs if str(t.get("state", "")).lower() == "pending"
        ]

    def drain_wallet(self, identifier: str) -> dict:
        """Drain all whole-satoshi funds from an isolated app to the primary wallet.

        Returns ``{"ok": True, "drained_sats": N, "dust_msat": M}``.
        Raises AlbyHubError on rejection or failure.
        """
        app = self._find_managed_app(identifier)
        if app is None:
            raise AlbyHubError("wallet_not_found", "Wallet connection not found.")

        app_id = int(app["id"])
        balance_msat = self._get_app_balance_msat(app)

        if balance_msat < 0:
            raise AlbyHubError("negative_balance", "Wallet has a negative balance.")

        pending = self._get_app_pending_txs(app_id)
        if pending:
            raise AlbyHubError(
                "pending_transactions",
                "Wallet has pending transactions and cannot be drained.",
            )

        transferable_msat = (balance_msat // 1000) * 1000
        expected_dust_msat = balance_msat - transferable_msat

        if transferable_msat == 0:
            return {"ok": True, "drained_sats": 0, "dust_msat": expected_dust_msat}

        # An internal wallet-to-wallet transfer does NOT require the isolated
        # source app to hold `pay_invoice`: the patched Alby Hub performs the
        # move authorized by the manager's full token without requiring the
        # source app to hold that scope. So no temporary scope grant (and the
        # associated privilege window) is needed here. This depends on the hub
        # `sovran` branch patch that lets internal `Transfer` skip the
        # source-app `pay_invoice` check.
        self._authenticated_request(
            "POST",
            "/api/transfers",
            body={
                "fromAppId": app_id,
                "amountMsat": transferable_msat,
                "description": f"Drain isolated subwallet {app.get('name', '')}",
            },
        )
        drained_sats = transferable_msat // 1000

        # Verify remaining balance equals expected dust
        refreshed = self._authenticated_request("GET", f"/api/v2/apps/{app_id}")
        remaining_msat = self._get_app_balance_msat(refreshed)
        if remaining_msat != expected_dust_msat:
            raise AlbyHubError(
                "drain_incomplete",
                "Drain verification failed: final balance does not match expected dust.",
            )

        # Audit log: wallet drained
        self._audit(
            "wallet_drained",
            wallet_id=str(app_id),
            name=app.get("name", ""),
            alias=self._app_alias(app),
            drained_sats=drained_sats,
            dust_msat=expected_dust_msat,
        )

        return {
            "ok": True,
            "drained_sats": drained_sats,
            "dust_msat": expected_dust_msat,
            "remaining_msat": remaining_msat,
        }

    def delete_wallet(self, identifier: str) -> dict:
        """Safely drain and delete an isolated app.

        Returns ``{"ok": True, "drained_sats": N}``.
        """
        app = self._find_managed_app(identifier)
        if app is None:
            raise AlbyHubError("wallet_not_found", "Wallet connection not found.")

        app_id = int(app["id"])

        pending = self._get_app_pending_txs(app_id)
        if pending:
            raise AlbyHubError(
                "pending_transactions",
                "Wallet has pending transactions and cannot be deleted.",
            )

        drain_result = self.drain_wallet(identifier)

        # Verify no transferable balance remains
        refreshed = self._authenticated_request("GET", f"/api/v2/apps/{app_id}")
        remaining_msat = self._get_app_balance_msat(refreshed)
        if remaining_msat < 0:
            raise AlbyHubError(
                "negative_balance",
                "Wallet has a negative final balance and cannot be deleted.",
            )
        if remaining_msat >= 1000:
            raise AlbyHubError(
                "drain_incomplete",
                f"Drain verification failed: funds still remain.",
            )

        # Delete by app pubkey
        pubkey = app.get("appPubkey") or app.get("nostrPubkey") or app.get("pubkey") or ""
        if not pubkey:
            raise AlbyHubError(
                "app_pubkey_missing",
                "Cannot delete app: nostr pubkey not available.",
            )
        self._authenticated_request(
            "DELETE",
            f"/api/apps/{urllib.parse.quote(pubkey, safe='')}",
        )

        # Audit log: wallet deleted
        self._audit(
            "wallet_deleted",
            wallet_id=str(app_id),
            name=app.get("name", ""),
            alias=self._app_alias(app),
            drained_sats=drain_result.get("drained_sats", 0),
            dust_msat=remaining_msat,
        )

        return {
            "ok": True,
            "drained_sats": drain_result.get("drained_sats", 0),
            "dust_msat": remaining_msat,
        }

    def issue_invoice(
        self, app_id: int, amount_msat: int, description: str = ""
    ) -> str:
        """Create an LND invoice attributed to a specific isolated app.

        Returns a valid BOLT11 invoice string.
        Raises AlbyHubError if the Hub returns an invalid or misattributed invoice.
        """
        resp = self._authenticated_request(
            "POST",
            "/api/invoices",
            body={
                "amountMsat": amount_msat,
                "description": description or LNURL_DESCRIPTION_DEFAULT,
                "toAppId": app_id,
            },
        )
        invoice: str = resp.get("invoice") or ""
        returned_app_id = resp.get("appId")

        if not invoice:
            raise AlbyHubError("invoice_creation_failed", "Hub returned empty invoice.")

        # Require a valid BOLT11 prefix (mainnet, testnet, signet, regtest)
        if not re.match(r"^ln", invoice, re.IGNORECASE):
            raise AlbyHubError(
                "invalid_invoice", "Hub returned a non-BOLT11 invoice string."
            )

        if returned_app_id is None or int(returned_app_id) != app_id:
            raise AlbyHubError(
                "invoice_attribution_failed",
                "Invoice attribution mismatch: returned appId does not match.",
            )

        # Audit log: invoice issued via API
        self._audit(
            "invoice_issued",
            app_id=app_id,
            amount_msat=amount_msat,
            amount_sat=amount_msat // 1000,
            invoice_prefix=invoice[:50] + "..." if len(invoice) > 50 else invoice,
        )

        return invoice

    def find_app_by_alias(self, alias: str) -> dict | None:
        """Find a managed isolated app by its ``lnurl_alias`` metadata field."""
        alias_lower = alias.strip().lower()
        for a in self._all_managed_apps():
            meta = self._parse_metadata(a.get("metadata"))
            if meta.get("lnurl_alias", "").lower() == alias_lower:
                return a
        return None

    def rotate_wallet_secret(self, identifier: str) -> dict:
        """Rotate the NWC pairing secret for a wallet connection.

        Revokes the old Nostr key and generates a new pairing URI.
        Returns the new pairing URI (shown ONCE).
        """
        app = self._find_managed_app(identifier)
        if app is None:
            raise AlbyHubError("wallet_not_found", "Wallet connection not found.")

        app_id = int(app["id"])
        app_pubkey = app.get("appPubkey") or app.get("nostrPubkey") or app.get("pubkey") or ""
        if not app_pubkey:
            raise AlbyHubError(
                "app_pubkey_missing",
                "Cannot rotate secret: app public key not available.",
            )

        # Call Alby Hub's rotate secret endpoint (if available)
        # Alby Hub may not have this endpoint yet; fall back to re-creating the app
        # For now, we'll delete and re-create with same metadata
        # This is a safe operation since we drain first
        name = app.get("name", "")
        alias = self._app_alias(app)
        scopes = app.get("scopes") or []
        max_amount = app.get("maxAmountSat") or 0
        metadata = app.get("metadata") or {}

        # Drain first
        self.drain_wallet(identifier)

        # Delete old app
        self._authenticated_request(
            "DELETE",
            f"/api/apps/{urllib.parse.quote(app_pubkey, safe='')}",
        )

        # Create new app with same parameters
        create_body: dict = {
            "name": name,
            "scopes": scopes,
            "isolated": True,
            "budgetRenewal": "never",
            "maxAmountSat": max_amount,
            "metadata": metadata,
        }

        resp = self._authenticated_request("POST", "/api/apps", body=create_body)
        new_pairing_uri: str = resp.get("pairingUri") or resp.get("pairing_uri") or ""
        new_app_id = resp.get("id")

        # Audit log: secret rotated
        self._audit(
            "wallet_secret_rotated",
            old_wallet_id=str(app_id),
            new_wallet_id=str(new_app_id) if new_app_id else "unknown",
            name=name,
            alias=alias,
        )

        return {
            "wallet_id": str(new_app_id) if new_app_id else "",
            "pairing_uri": new_pairing_uri,
            "message": "New NWC connection secret generated. Save it now — it will not be shown again.",
        }

    def health(self) -> dict:
        """Return a basic health summary."""
        try:
            token = self.ensure_ready()
            status = self._request(
                "GET", "/api/node/status", token=token, timeout=10
            )
            return {
                "ok": True,
                "hub_ready": bool(
                    status.get("isReady") or status.get("running")
                ),
            }
        except AlbyHubError as exc:
            return {"ok": False, "error": exc.code, "message": str(exc)}


# ── Module-level singleton ──────────────────────────────────────────

_manager: AlbyHubManager | None = None
_manager_lock = threading.Lock()


def get_manager() -> AlbyHubManager:
    """Return the module-level singleton AlbyHubManager."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = AlbyHubManager()
    return _manager
