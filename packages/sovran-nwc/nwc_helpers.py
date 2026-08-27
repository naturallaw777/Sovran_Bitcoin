"""Standalone helpers for the Sovran NWC tools.

Extracted from Sovran_SystemsOS' Hub web app (``sovran_systemsos_web/server.py``)
so that ``nwc-wallet`` and the LNURL service can run without the full Hub.

Domain resolution order:
  1. ``NWC_LNURL_DOMAIN`` environment variable (set directly by the NixOS module)
  2. ``NWC_LNURL_DOMAIN_FILE`` (default ``/var/lib/domains/lightning``)
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

# NOTE: The equivalent pattern in Sovran_SystemsOS modules/core/local-domain-loopback.nix
# (shell grep -E) must be kept in sync with this Python regex.
_SAFE_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

NWC_ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

DOMAIN_FILE = os.environ.get("NWC_LNURL_DOMAIN_FILE", "/var/lib/domains/lightning")


def _validate_domain_value(domain: str) -> bool:
    """Return True if *domain* is a valid hostname.

    Rejects values containing whitespace, newlines, or other characters that
    could inject additional entries or corrupt files.
    """
    if not domain or len(domain) > 253:
        return False
    # Guard against newline / whitespace injection before regex check.
    if any(c in domain for c in ('\n', '\r', ' ', '\t', '#')):
        return False
    return bool(_SAFE_DOMAIN_RE.match(domain))


def _nwc_domain() -> str | None:
    env_domain = os.environ.get("NWC_LNURL_DOMAIN", "").strip().lower()
    if env_domain:
        return env_domain if _validate_domain_value(env_domain) else None
    try:
        with open(DOMAIN_FILE, "r") as f:
            domain = f.read(256).strip().lower()
    except OSError:
        return None
    if not _validate_domain_value(domain):
        return None
    return domain


def _nwc_validate_alias(alias: str) -> bool:
    return bool(NWC_ALIAS_RE.match(alias))


def _nwc_test_address(alias: str) -> dict:
    domain = _nwc_domain()
    if not domain:
        return {"ok": False, "error": "domain_not_configured", "message": "Lightning domain is not configured."}
    url = f"https://{domain}/.well-known/lnurlp/{alias}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            if int(resp.status) >= 400:
                return {"ok": False, "error": "public_endpoint_unreachable", "message": f"Public LNURL discovery endpoint returned HTTP {resp.status}."}
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return {"ok": False, "error": "public_endpoint_unreachable", "message": "Public LNURL endpoint verification failed."}
    if payload.get("tag") != "payRequest":
        return {"ok": False, "error": "public_endpoint_unreachable", "message": "Discovery endpoint returned an invalid LNURL response."}
    return {"ok": True}
