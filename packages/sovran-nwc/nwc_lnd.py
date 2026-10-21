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
import secrets
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


# lnrpc.PaymentFailureReason → human-readable payment failure message
_FAILURE_REASONS = {
    "FAILURE_REASON_TIMEOUT": "Payment timeout: no route found in time",
    "FAILURE_REASON_NO_ROUTE": "No route found to destination",
    "FAILURE_REASON_ERROR": "Payment failed due to an error",
    "FAILURE_REASON_INCORRECT_PAYMENT_DETAILS": "Payment details incorrect",
    "FAILURE_REASON_INSUFFICIENT_BALANCE": "Insufficient balance for payment",
    "FAILURE_REASON_INVOICE_EXPIRED": "Invoice expired",
}


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
        # Pin the protocol floor explicitly: create_default_context() defaults
        # to TLS 1.2+, and LND has supported TLS 1.2 since 0.4. Explicit here
        # because py/insecure-protocol (CWE-327) cannot model the implicit
        # default and flags the bare call.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # LND certs on 127.0.0.1 include IP:127.0.0.1 and DNS:localhost
        return ctx

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        raw = self.request_text(method, path, body=body, timeout=timeout)
        if not raw:
            return {}
        return json.loads(raw)

    def request_text(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> str:
        """Perform a request and return the raw response body as text.

        Used for streaming endpoints (e.g. `POST /v2/router/send`) whose body
        is a sequence of JSON documents rather than a single object.
        """
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
                return raw.decode("utf-8") if raw else ""
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
            "fee_limit_msat": str(int(fee_limit_msat)),
        }
        if amount_msat is not None and amount_msat > 0:
            body["amt_msat"] = str(int(amount_msat))
        return self.send_payment_v2(body, fee_limit_msat=fee_limit_msat)

    def pay_keysend(
        self,
        dest_pubkey_hex: str,
        amount_msat: int,
        fee_limit_msat: int,
        preimage_hex: str = "",
        tlv_records: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Send a keysend (spontaneous) payment via SendPaymentV2.

        The keysend preimage rides in TLV record 5482373484. `preimage_hex`
        (hex) is used when given, otherwise one is generated; any extra
        `tlv_records` ({type, value(hex)}) are merged in as custom records.
        """
        preimage = bytes.fromhex(preimage_hex) if preimage_hex else secrets.token_bytes(32)
        records: dict[str, str] = {}
        for rec in tlv_records or []:
            try:
                rtype = str(int(rec.get("type") or 0))
                value_hex = str(rec.get("value") or "")
                if rtype and rtype != "0" and value_hex:
                    records[rtype] = base64.b64encode(bytes.fromhex(value_hex)).decode("ascii")
            except ValueError:
                continue
        # The keysend preimage record always wins over caller-supplied TLVs.
        records["5482373484"] = base64.b64encode(preimage).decode("ascii")

        body: dict[str, Any] = {
            "dest": base64.b64encode(bytes.fromhex(dest_pubkey_hex.strip())).decode("ascii"),
            "amt_msat": str(int(amount_msat)),
            "fee_limit_msat": str(int(fee_limit_msat)),
            "dest_custom_records": records,
        }
        result = self.send_payment_v2(body, fee_limit_msat=fee_limit_msat)
        # Trust LND's returned preimage; fall back to the one we sent.
        if not result.get("preimage"):
            result["preimage"] = preimage.hex()
        return result

    def send_payment_v2(
        self,
        body: dict[str, Any],
        fee_limit_msat: int,
    ) -> dict[str, Any]:
        # LND 0.21 removed the deprecated `POST /v1/channels/transactions`
        # (lnrpc.SendPaymentSync) REST route; payments are sent through
        # routerrpc.SendPaymentV2 (`POST /v2/router/send`), which streams
        # `lnrpc.Payment` updates (terminal state only with
        # `no_inflight_updates`) as newline-delimited JSON.
        body = dict(body)
        body.setdefault("fee_limit_msat", str(int(fee_limit_msat)))
        body["allow_self_payment"] = True
        body["no_inflight_updates"] = True
        body.setdefault("timeout_seconds", 60)

        raw = self.request_text("POST", "/v2/router/send", body=body, timeout=120)
        updates = self.parse_json_stream(raw)
        if not updates:
            raise LndPaymentError("LND returned no payment status")
        payment = updates[-1]
        # Some gateways wrap stream items as {"result": {...}}; unwrap so the
        # lnrpc.Payment fields are read from the right level.
        if isinstance(payment.get("result"), dict):
            payment = payment["result"]

        status = str(payment.get("status") or "").upper()
        # In lnrpc.Payment the hash and preimage are hex strings (not base64).
        payment_hash_hex = str(payment.get("payment_hash") or "").lower()
        preimage_hex = str(payment.get("payment_preimage") or "").lower()
        fees_msat = int(payment.get("fee_msat") or 0)
        if fees_msat == 0 and payment.get("fee_sat") is not None:
            fees_msat = int(payment.get("fee_sat") or 0) * 1000

        if status == "SUCCEEDED":
            return {
                "preimage": preimage_hex,
                "payment_hash": payment_hash_hex,
                "fees_paid_msat": fees_msat,
            }

        if status == "FAILED":
            reason = str(payment.get("failure_reason") or "").strip()
            human = (
                _FAILURE_REASONS.get(reason)
                or _FAILURE_REASONS.get("FAILURE_REASON_" + reason)
                or reason
                or "payment failed"
            )
            raise LndPaymentError(human)

        raise LndPaymentError(
            f"Payment did not reach a terminal state (status={status or 'unknown'})"
        )

    @staticmethod
    def parse_json_stream(raw: str) -> list[dict[str, Any]]:
        """Parse a gRPC-gateway streaming body: one or more JSON documents.

        Streaming REST responses are newline-delimited JSON objects; also
        tolerate concatenated objects and a single document.
        """
        out: list[dict[str, Any]] = []
        text = raw.strip()
        if not text:
            return out
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(text):
            while idx < len(text) and text[idx].isspace():
                idx += 1
            if idx >= len(text):
                break
            try:
                value, end = decoder.raw_decode(text, idx)
            except ValueError:
                break
            if isinstance(value, dict):
                out.append(value)
            idx = end
        return out
