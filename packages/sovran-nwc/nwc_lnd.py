"""Pure-stdlib LND REST client for Sovran NWC.

Communicates directly with LND's built-in HTTPS REST interface
(default https://127.0.0.1:8080) using the node's TLS certificate and
scoped macaroon (`Grpc-Metadata-macaroon`).

Enforces Sovran's privacy default (`private=True` on all created invoices so
private route hints are always included).
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class LndError(Exception):
    """Error communicating with LND REST API."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LndPaymentError(LndError):
    """Payment routing/execution failure returned by LND."""

    def __init__(self, message: str) -> None:
        super().__init__("PAYMENT_FAILED", message)


class LndRestClient:
    """Thread-safe LND REST API client using Python stdlib ssl + urllib."""

    def __init__(
        self,
        rest_url: str = "https://127.0.0.1:8080",
        cert_file: str = "/etc/nix-bitcoin-secrets/lnd-cert",
        macaroon_file: str = "/run/lnd/albyhub.macaroon",
    ) -> None:
        self.rest_url = rest_url.rstrip("/")
        self.cert_file = cert_file
        self.macaroon_file = macaroon_file
        self._macaroon_hex: str | None = None
        self._macaroon_mtime: float = 0.0

    def _get_macaroon_hex(self) -> str:
        try:
            st = os.stat(self.macaroon_file)
            if self._macaroon_hex and st.st_mtime == self._macaroon_mtime:
                return self._macaroon_hex
            with open(self.macaroon_file, "rb") as fh:
                raw = fh.read()
            if not raw:
                raise OSError("Macaroon file is empty")
            self._macaroon_hex = raw.hex()
            self._macaroon_mtime = st.st_mtime
            return self._macaroon_hex
        except OSError as exc:
            raise LndError(
                "macaroon_unavailable",
                f"Cannot read LND macaroon at {self.macaroon_file}",
            ) from exc

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.rest_url.lower().startswith("https://"):
            return None
        if not os.path.exists(self.cert_file):
            raise LndError(
                "cert_unavailable",
                f"Cannot read LND TLS certificate at {self.cert_file}",
            )
        ctx = ssl.create_default_context(cafile=self.cert_file)
        # LND certs on 127.0.0.1 include IP:127.0.0.1 and DNS:localhost
        return ctx

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        mac_hex = self._get_macaroon_hex()
        url = f"{self.rest_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Accept": "application/json",
            "Grpc-Metadata-macaroon": mac_hex,
        }
        if data is not None:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        ctx = self._ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_msg = f"LND {method} {path} returned HTTP {exc.code}"
            try:
                err_raw = exc.read().decode("utf-8", errors="replace")
                err_json = json.loads(err_raw)
                if isinstance(err_json, dict) and err_json.get("message"):
                    err_msg = str(err_json["message"])
            except Exception:
                pass
            if exc.code == 404:
                raise LndError("NOT_FOUND", err_msg) from None
            raise LndError(f"http_{exc.code}", err_msg) from None
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            raise LndError(
                "lnd_unreachable", f"LND REST API {path} unreachable: {type(exc).__name__}"
            ) from None

    # ── High-level LND operations ──────────────────────────────────

    def get_info(self) -> dict[str, Any]:
        resp = self.request("GET", "/v1/getinfo", timeout=10)
        chains = resp.get("chains") or []
        network = "mainnet"
        if chains and isinstance(chains[0], dict):
            network = str(chains[0].get("network") or "mainnet")
        return {
            "pubkey": str(resp.get("identity_pubkey") or ""),
            "alias": str(resp.get("alias") or ""),
            "color": str(resp.get("color") or "#000000"),
            "block_height": int(resp.get("block_height") or 0),
            "block_hash": str(resp.get("block_hash") or ""),
            "network": network,
            "synced_to_chain": bool(resp.get("synced_to_chain", True)),
        }

    def get_channel_balance_msat(self) -> int:
        resp = self.request("GET", "/v1/balance/channels", timeout=10)
        local_bal = resp.get("local_balance")
        if isinstance(local_bal, dict) and local_bal.get("msat") is not None:
            return int(local_bal["msat"])
        if resp.get("balance") is not None:
            return int(resp["balance"]) * 1000
        return 0

    def create_invoice(
        self,
        amount_msat: int,
        memo: str = "",
        expiry: int = 3600,
        description_hash_hex: str | None = None,
        private: bool = True,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "value_msat": str(int(amount_msat)),
            "memo": memo or "",
            "expiry": str(int(expiry)),
            # Sovran privacy opinion: always include private route hints
            "private": bool(private),
        }
        if description_hash_hex:
            body["description_hash"] = base64.b64encode(
                bytes.fromhex(description_hash_hex)
            ).decode("ascii")

        resp = self.request("POST", "/v1/invoices", body=body, timeout=20)
        payment_request = str(resp.get("payment_request") or "")
        r_hash_b64 = str(resp.get("r_hash") or "")
        payment_hash = base64.b64decode(r_hash_b64).hex() if r_hash_b64 else ""
        now = int(time.time())
        return {
            "invoice": payment_request,
            "payment_hash": payment_hash.lower(),
            "amount_msat": int(amount_msat),
            "description": memo or "",
            "description_hash": (description_hash_hex or "").lower(),
            "created_at": now,
            "expires_at": now + int(expiry),
        }

    def lookup_invoice(self, payment_hash_hex: str) -> dict[str, Any]:
        r_hash_hex = payment_hash_hex.strip().lower()
        resp = self.request("GET", f"/v1/invoice/{r_hash_hex}", timeout=15)
        raw_state = str(resp.get("state") or "").upper()
        if raw_state == "SETTLED" or resp.get("settled") is True:
            state = "settled"
        elif raw_state == "CANCELED":
            state = "failed"
        else:
            state = "pending"

        amt_msat = int(
            resp.get("amt_paid_msat")
            or resp.get("value_msat")
            or (int(resp.get("value") or 0) * 1000)
        )
        created_at = int(resp.get("creation_date") or time.time())
        expiry = int(resp.get("expiry") or 3600)
        settle_date = int(resp.get("settle_date") or 0)
        preimage_b64 = resp.get("r_preimage") or ""
        preimage_hex = ""
        if preimage_b64:
            try:
                raw_pre = base64.b64decode(preimage_b64)
                if any(b != 0 for b in raw_pre):
                    preimage_hex = raw_pre.hex()
            except Exception:
                pass
        desc_hash_b64 = resp.get("description_hash") or ""
        desc_hash_hex = ""
        if desc_hash_b64:
            try:
                raw_dh = base64.b64decode(desc_hash_b64)
                if any(b != 0 for b in raw_dh):
                    desc_hash_hex = raw_dh.hex()
            except Exception:
                pass
        return {
            "payment_hash": r_hash_hex,
            "invoice": str(resp.get("payment_request") or ""),
            "state": state,
            "amount_msat": amt_msat,
            "created_at": created_at,
            "expires_at": created_at + expiry,
            "settled_at": settle_date if settle_date > 0 else None,
            "description": str(resp.get("memo") or ""),
            "description_hash": desc_hash_hex,
            "preimage": preimage_hex,
        }

    def decode_payreq(self, bolt11: str) -> dict[str, Any]:
        quoted = urllib.parse.quote(bolt11.strip(), safe="")
        resp = self.request("GET", f"/v1/payreq/{quoted}", timeout=15)
        amt_msat = int(
            resp.get("num_msat")
            or (int(resp.get("num_satoshis") or 0) * 1000)
        )
        ts = int(resp.get("timestamp") or time.time())
        expiry = int(resp.get("expiry") or 3600)
        return {
            "destination": str(resp.get("destination") or ""),
            "payment_hash": str(resp.get("payment_hash") or "").lower(),
            "amount_msat": amt_msat,
            "timestamp": ts,
            "expiry": expiry,
            "expires_at": ts + expiry,
            "description": str(resp.get("description") or ""),
            "description_hash": str(resp.get("description_hash") or "").lower(),
        }

    def pay_invoice(
        self,
        bolt11: str,
        fee_limit_msat: int,
        amount_msat: int | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "payment_request": bolt11.strip(),
            "fee_limit": {"fixed_msat": str(int(fee_limit_msat))},
            "allow_self_payment": True,
        }
        if amount_msat is not None and amount_msat > 0:
            body["amt_msat"] = str(int(amount_msat))

        resp = self.request(
            "POST", "/v1/channels/transactions", body=body, timeout=60
        )
        pay_err = str(resp.get("payment_error") or "").strip()
        if pay_err:
            raise LndPaymentError(pay_err)

        preimage_b64 = str(resp.get("payment_preimage") or "")
        preimage_hex = (
            base64.b64decode(preimage_b64).hex() if preimage_b64 else ""
        )
        hash_b64 = str(resp.get("payment_hash") or "")
        payment_hash_hex = (
            base64.b64decode(hash_b64).hex() if hash_b64 else ""
        )
        route = resp.get("payment_route") or {}
        fees_msat = int(route.get("total_fees_msat") or 0)
        return {
            "preimage": preimage_hex.lower(),
            "payment_hash": payment_hash_hex.lower(),
            "fees_paid_msat": fees_msat,
        }
