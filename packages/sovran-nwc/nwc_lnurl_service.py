"""
Dedicated LNURL service for Lightning Wallet Connections.

Runs as ``nwc-lnurl.service`` on 127.0.0.1:8181 (loopback only).
Caddy proxies the public Lightning Address domain's LNURL routes to this port.

Routes:
  GET /.well-known/lnurlp/{alias}
  GET /lnurlp/{alias}/callback?amount=<msat>

All error responses are safe for public consumption — raw Alby Hub bodies
and internal credentials are never returned to callers.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time
import urllib.parse
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

from . import nwc_hub_manager as _mgr_mod
from . import nwc_audit as _audit_mod

if TYPE_CHECKING:
    from .nwc_hub_manager import AlbyHubManager

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────

LNURL_BIND_HOST = os.environ.get("NWC_LNURL_BIND_HOST", "127.0.0.1")
LNURL_PORT = int(os.environ.get("NWC_LNURL_PORT", "8181"))
DOMAIN_FILE = os.environ.get("NWC_LNURL_DOMAIN_FILE", "/var/lib/domains/lightning")

NWC_ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

# Rate limiting configuration (all tunable via env)
RATE_LIMIT_WINDOW_SEC = int(os.environ.get("NWC_LNURL_RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("NWC_LNURL_RATE_LIMIT_MAX", "30"))
# Separate, stricter per-Lightning-Address budget so a single alias cannot be
# hammered to mint invoices regardless of the source IP.
RATE_LIMIT_MAX_PER_ALIAS = int(os.environ.get("NWC_LNURL_RATE_LIMIT_MAX_PER_ALIAS", "10"))
_rate_limit_buckets: dict[str, list[float]] = defaultdict(list)
_rate_limit_alias_buckets: dict[str, list[float]] = defaultdict(list)

# ── Helpers ───────────────────────────────────────────────────────


def _read_domain() -> str | None:
    raw = None
    # NWC_LNURL_DOMAIN takes precedence over the domain file so the NixOS
    # module can set the Lightning Address domain directly.
    env_domain = os.environ.get("NWC_LNURL_DOMAIN", "").strip().lower()
    if env_domain:
        raw = env_domain[:256]
    else:
        try:
            with open(DOMAIN_FILE, "r") as fh:
                raw = fh.read(256).strip().lower()
        except OSError:
            return None
    if raw is None:
        return None
    try:
        # Strict FQDN validation: must be a valid hostname with at least one dot
        # Reject localhost, IP addresses, and single-label names
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", raw):
            return None
        # Explicitly reject local/reserved names
        if raw in {"localhost", "localhost.localdomain", "local"}:
            return None
        return raw
    except (TypeError, ValueError):
        return None


def _check_rate_limit(client_ip: str) -> bool:
    """Check and update rate limit bucket for client IP. Returns True if allowed."""
    now = time.monotonic()
    bucket = _rate_limit_buckets[client_ip]
    # Prune old entries
    cutoff = now - RATE_LIMIT_WINDOW_SEC
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    bucket.append(now)
    return True


def _check_alias_rate_limit(alias: str) -> bool:
    """Check and update the per-Lightning-Address rate limit bucket.

    Returns True if allowed. `alias` is always regex-validated by the caller
    before reaching this point, so it is safe to use as a dict key.
    """
    now = time.monotonic()
    bucket = _rate_limit_alias_buckets[alias]
    cutoff = now - RATE_LIMIT_WINDOW_SEC
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= RATE_LIMIT_MAX_PER_ALIAS:
        return False
    bucket.append(now)
    return True


def _lnurl_discovery(alias: str, manager: "AlbyHubManager", client_ip: str = "") -> tuple[dict, int]:
    alias = alias.strip().lower()
    if not NWC_ALIAS_RE.match(alias):
        return {"status": "ERROR", "reason": "Unknown Lightning Address alias"}, 404

    domain = _read_domain()
    if not domain:
        return {"status": "ERROR", "reason": "Lightning domain is not configured"}, 503

    try:
        app = manager.find_app_by_alias(alias)
    except _mgr_mod.AlbyHubError:
        return {"status": "ERROR", "reason": "Service temporarily unavailable"}, 503

    if app is None:
        return {"status": "ERROR", "reason": "Unknown Lightning Address alias"}, 404

    meta = _mgr_mod.AlbyHubManager._parse_metadata(app.get("metadata"))
    min_sendable = int(
        meta.get("lnurl_min_sendable_msat", _mgr_mod.NWC_MIN_SENDABLE_MSAT)
    )
    max_sendable = int(
        meta.get("lnurl_max_sendable_msat", _mgr_mod.NWC_MAX_SENDABLE_MSAT)
    )

    callback_alias = urllib.parse.quote(alias, safe="")
    callback = f"https://{domain}/lnurlp/{callback_alias}/callback"
    description = meta.get("lnurl_description") or f"Pay {alias}"
    metadata = json.dumps([["text/plain", description]], separators=(",", ":"))

    # Audit log: LNURL discovery
    _audit_mod.audit_log(
        "lnurl_discovery",
        alias=alias,
        domain=domain,
        client_ip=client_ip,
        min_sendable_msat=min_sendable,
        max_sendable_msat=max_sendable,
    )

    return {
        "tag": "payRequest",
        "callback": callback,
        "minSendable": min_sendable,
        "maxSendable": max_sendable,
        "metadata": metadata,
        "commentAllowed": 0,
    }, 200


def _lnurl_callback(
    alias: str, amount_str: str | None, manager: "AlbyHubManager", client_ip: str = ""
) -> tuple[dict, int]:
    payload, status_code = _lnurl_discovery(alias, manager, client_ip)
    if status_code != 200:
        return payload, status_code

    if amount_str is None:
        return {"status": "ERROR", "reason": "Missing amount parameter"}, 400
    if not re.match(r"^\d+$", amount_str):
        return {
            "status": "ERROR",
            "reason": "Amount must be an integer millisatoshi value",
        }, 400

    amount_msat = int(amount_str)
    min_sendable = int(payload["minSendable"])
    max_sendable = int(payload["maxSendable"])

    if amount_msat < min_sendable:
        return {
            "status": "ERROR",
            "reason": "Amount is below the minimum sendable value",
        }, 400
    if amount_msat > max_sendable:
        return {
            "status": "ERROR",
            "reason": "Amount is above the maximum sendable value",
        }, 400
    if amount_msat % 1000 != 0:
        return {
            "status": "ERROR",
            "reason": "Amount must be a whole-satoshi value",
        }, 400

    try:
        app = manager.find_app_by_alias(alias)
    except _mgr_mod.AlbyHubError:
        return {"status": "ERROR", "reason": "Service temporarily unavailable"}, 503

    if app is None:
        return {"status": "ERROR", "reason": "Unknown Lightning Address alias"}, 404

    meta = _mgr_mod.AlbyHubManager._parse_metadata(app.get("metadata"))
    description = meta.get("lnurl_description") or f"Pay {alias}"

    try:
        app_id = int(app["id"])
        invoice = manager.issue_invoice(app_id, amount_msat, description)
    except _mgr_mod.AlbyHubError:
        return {"status": "ERROR", "reason": "Invoice creation failed"}, 502

    # Audit log: Invoice generated via LNURL
    _audit_mod.audit_log(
        "lnurl_invoice_created",
        alias=alias,
        amount_msat=amount_msat,
        amount_sat=amount_msat // 1000,
        client_ip=client_ip,
        invoice_prefix=invoice[:50] + "..." if len(invoice) > 50 else invoice,
    )

    return {"pr": invoice, "routes": []}, 200


# ── HTTP server ───────────────────────────────────────────────────


def _make_handler(manager: "AlbyHubManager") -> type:
    """Return a handler class bound to the given manager."""

    class LnurlHandler(BaseHTTPRequestHandler):
        _manager = manager

        def log_message(self, fmt: str, *args: object) -> None:
            logger.debug(f"LNURL {self.address_string()} {fmt % args}")

        def _send_json(self, status: int, body: dict) -> None:
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _get_client_ip(self) -> str:
            # Check X-Forwarded-For header (set by Caddy)
            forwarded = self.headers.get("X-Forwarded-For")
            if forwarded:
                # Take the first IP in the chain (trusts the proxy to set this).
                candidate = forwarded.split(",")[0].strip()
            else:
                candidate = self.client_address[0]
            # Validate the IP so a malformed/forged value cannot be used as a
            # rate-limit key or written (unescaped) into the audit log.
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                return "unknown"

        def _check_rate_limit(self) -> bool:
            client_ip = self._get_client_ip()
            if not _check_rate_limit(client_ip):
                self._send_json(429, {
                    "status": "ERROR",
                    "reason": "Rate limit exceeded. Please slow down."
                })
                _audit_mod.audit_log(
                    "rate_limit_exceeded",
                    client_ip=client_ip,
                    path=self.path,
                )
                return False
            return True

        def _check_alias_rate_limit(self, alias: str) -> bool:
            if not _check_alias_rate_limit(alias):
                self._send_json(429, {
                    "status": "ERROR",
                    "reason": "Rate limit exceeded for this Lightning Address. Please slow down.",
                })
                _audit_mod.audit_log(
                    "rate_limit_exceeded",
                    alias=alias,
                    path=self.path,
                )
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self._check_rate_limit():
                return

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)
            client_ip = self._get_client_ip()

            # /.well-known/lnurlp/{alias}
            m = re.fullmatch(
                r"/.well-known/lnurlp/([^/]+)", path
            )
            if m:
                alias = urllib.parse.unquote(m.group(1))
                if not self._check_alias_rate_limit(alias):
                    return
                payload, code = _lnurl_discovery(alias, self._manager, client_ip)
                self._send_json(code, payload)
                return

            # /lnurlp/{alias}/callback
            m = re.fullmatch(r"/lnurlp/([^/]+)/callback", path)
            if m:
                alias = urllib.parse.unquote(m.group(1))
                if not self._check_alias_rate_limit(alias):
                    return
                amount_values = qs.get("amount")
                if not amount_values:
                    amount_str = None
                elif len(amount_values) != 1:
                    self._send_json(
                        400,
                        {
                            "status": "ERROR",
                            "reason": "A single amount parameter is required",
                        },
                    )
                    return
                else:
                    amount_str = amount_values[0]
                payload, code = _lnurl_callback(alias, amount_str, self._manager, client_ip)
                self._send_json(code, payload)
                return

            self._send_json(404, {"status": "ERROR", "reason": "Not found"})

    return LnurlHandler


def run(
    host: str = LNURL_BIND_HOST,
    port: int = LNURL_PORT,
    manager: "AlbyHubManager | None" = None,
) -> None:
    """Start the blocking LNURL HTTP server."""
    if manager is None:
        manager = _mgr_mod.get_manager()
    handler_class = _make_handler(manager)
    server = HTTPServer((host, port), handler_class)
    logger.info("nwc-lnurl service listening on %s:%d", host, port)
    server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    run()


if __name__ == "__main__":
    main()
