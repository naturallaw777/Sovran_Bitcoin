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
import shutil
import subprocess
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


# ── Bech32 encoding (BIP-173) — used for LNURL strings (LUD-01) ──

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _bech32_polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _BECH32_GENERATOR[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]


def _bech32_convertbits(data: bytes, frombits: int, tobits: int) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def _bech32_encode(hrp: str, payload: bytes) -> str:
    """Encode payload bytes as a bech32 string with the given HRP (BIP-173)."""
    data = _bech32_convertbits(payload, 8, 5)
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)


def _nwc_lnurl_bech32(alias: str, domain: str) -> str:
    """Return the LUD-01 bech32 LNURL for a wallet connection alias."""
    url = f"https://{domain}/.well-known/lnurlp/{alias}"
    return _bech32_encode("lnurl", url.encode("utf-8"))


def _nwc_lightning_address(alias: str, domain: str | None) -> str | None:
    """Return the Lightning Address for an alias, or None if domain is unavailable."""
    if not domain:
        return None
    return f"{alias}@{domain}"


def _render_qr_terminal(data: str) -> str | None:
    """Render a QR code as ANSI text for terminal display.

    Uses ``qrencode -t ANSIUTF8`` if available on PATH.  Returns None if
    qrencode is not installed.
    """
    qrencode = shutil.which("qrencode")
    if qrencode is None:
        return None
    try:
        result = subprocess.run(
            [qrencode, "-t", "ANSIUTF8", "-l", "H", data],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except Exception:
        pass
    return None
