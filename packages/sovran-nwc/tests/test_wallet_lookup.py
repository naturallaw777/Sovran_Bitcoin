"""Tests for `nwc-wallet` wallet resolution (lookup by name/alias/id/pubkey).

Regression test for: "nwc wallet delete is not working — when one types in a
wallet name it can't find it even though it is in the list".

Runs a fake Alby Hub API on localhost (stdlib only, no network) and drives
`AlbyHubManager` against it, plus the `nwc-wallet` CLI entrypoint.

Run with:  python3 -m unittest discover -s packages/sovran-nwc/tests -v
"""

from __future__ import annotations

import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import types

# The modules use relative imports (`from . import nwc_audit`), so expose the
# package root under the same name the Nix wrapper uses.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if "sovran_nwc" not in sys.modules:
    _pkg = types.ModuleType("sovran_nwc")
    _pkg.__path__ = [_PKG_ROOT]  # type: ignore[attr-defined]
    sys.modules["sovran_nwc"] = _pkg

from sovran_nwc import nwc_hub_manager as mgr_mod  # noqa: E402
from sovran_nwc import nwc_wallet_cli as cli_mod  # noqa: E402


# ── Fake Alby Hub ──────────────────────────────────────────────────

MANAGED_META = {
    "app_store_app_id": "uncle-jim",
}


def make_app(
    app_id: int,
    name: str,
    alias: str,
    pubkey: str | None = None,
    balance_msat: int = 0,
    isolated: bool = True,
    managed: bool = True,
) -> dict:
    meta = dict(MANAGED_META) if managed else {}
    if alias:
        meta["lnurl_alias"] = alias
    return {
        "id": app_id,
        "name": name,
        "isolated": isolated,
        "appPubkey": pubkey or f"npub{app_id}" + "0" * 50,
        "nostrPubkey": pubkey or f"npub{app_id}" + "0" * 50,
        "balanceMsat": balance_msat,
        "scopes": ["get_info", "get_balance", "make_invoice"],
        "metadata": meta,
        "createdAt": "2026-01-01T00:00:00Z",
    }


class FakeHub:
    """Minimal in-memory stand-in for the Alby Hub REST API."""

    def __init__(self, apps: list[dict]) -> None:
        self.apps = {int(a["id"]): dict(a) for a in apps}
        self.transactions: list[dict] = []
        self.deleted: list[str] = []
        self.transfers: list[dict] = []
        self.created: list[dict] = []
        self._server: ThreadingHTTPServer | None = None

    # -- request handling ------------------------------------------------
    def handle(self, method: str, path: str, body: dict | None) -> tuple[int, object]:
        route = path.split("?")[0]

        if route == "/api/info":
            return 200, {"setupCompleted": True, "running": True}
        if route in ("/api/unlock", "/api/start"):
            return 200, {"token": "test-token"}
        if route == "/api/node/status":
            return 200, {"isReady": True, "running": True}

        if route == "/api/apps" and method == "GET":
            return 200, {"apps": list(self.apps.values()), "totalCount": len(self.apps)}
        if route == "/api/apps" and method == "POST":
            new_id = max(self.apps.keys(), default=0) + 1
            app = dict(body or {})
            app["id"] = new_id
            app.setdefault("balanceMsat", 0)
            app.setdefault("appPubkey", f"npub{new_id}" + "0" * 50)
            self.apps[new_id] = app
            self.created.append(app)
            return 200, dict(app, pairingUri="nostr+walletconnect://newsecret")

        parts = route.strip("/").split("/")
        # /api/apps/<pubkey>
        if route.startswith("/api/apps/") and method == "DELETE" and len(parts) == 3:
            pubkey = parts[2]
            self.deleted.append(pubkey)
            for app_id, app in list(self.apps.items()):
                if app.get("appPubkey") == pubkey:
                    del self.apps[app_id]
            return 200, {}

        # /api/v2/apps/<id>
        if route.startswith("/api/v2/apps/") and method == "GET":
            app_id = int(parts[-1])
            app = self.apps.get(app_id)
            if app is None:
                return 404, {"error": "not found"}
            return 200, app

        if route == "/api/transactions" and method == "GET":
            return 200, {"transactions": self.transactions, "totalCount": len(self.transactions)}

        if route == "/api/transfers" and method == "POST":
            self.transfers.append(body or {})
            amount = (body or {}).get("amountMsat") or (
                (body or {}).get("amountSat", 0) * 1000
            )
            src = (body or {}).get("fromAppId")
            dst = (body or {}).get("toAppId")
            if src is not None and int(src) in self.apps:
                app = self.apps[int(src)]
                app["balanceMsat"] = int(app.get("balanceMsat", 0)) - int(amount)
            if dst is not None and int(dst) in self.apps:
                app = self.apps[int(dst)]
                app["balanceMsat"] = int(app.get("balanceMsat", 0)) + int(amount)
            return 200, {"ok": True}

        return 404, {"error": f"unhandled {method} {route}"}

    # -- server lifecycle ------------------------------------------------
    def __enter__(self) -> "FakeHub":
        hub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence test noise
                pass

            def _dispatch(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else None
                status, payload = hub.handle(method, self.path, body)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._dispatch("GET")

            def do_POST(self):
                self._dispatch("POST")

            def do_DELETE(self):
                self._dispatch("DELETE")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(
            target=self._server.serve_forever, args=(0.05,), daemon=True
        ).start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def base_url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"


# ── Fixtures ───────────────────────────────────────────────────────

APPS = [
    make_app(1, "Savings", "savings", balance_msat=12_000),
    make_app(2, "Shop Till", "shop", balance_msat=500),
    make_app(3, "Car Fund", "car-fund"),
    # unmanaged / non-isolated apps must never be resolvable or deletable
    make_app(4, "Decoy Unmanaged", "decoy", managed=False),
    make_app(5, "Decoy NonIsolated", "decoy2", isolated=False),
]


def build_manager(hub: FakeHub) -> mgr_mod.AlbyHubManager:
    manager = mgr_mod.AlbyHubManager(api_base=hub.base_url)
    manager._token = "test-token"  # skip unlock/setup dance
    return manager


def _loopback_usable() -> bool:
    """These tests bind a local HTTP server; skip where that is not allowed."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


class WalletLookupTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not _loopback_usable():
            raise unittest.SkipTest("loopback sockets unavailable (sandboxed build?)")

    def setUp(self) -> None:
        self._hub = FakeHub([dict(a) for a in APPS]).__enter__()
        self.addCleanup(self._hub.__exit__)
        self.manager = build_manager(self._hub)

        # Point the CLI's singleton at our manager + fake hub
        self._orig_get_manager = mgr_mod.get_manager
        mgr_mod.get_manager = lambda: self.manager  # type: ignore[assignment]
        self.addCleanup(setattr, mgr_mod, "get_manager", self._orig_get_manager)
        cli_mod._mgr_mod.get_manager = mgr_mod.get_manager  # type: ignore[assignment]

    # -- the reported bug -----------------------------------------------
    def test_delete_by_name(self) -> None:
        """`nwc-wallet delete <name>` must find a wallet shown by `nwc-wallet list`."""
        listed = {w["name"]: w for w in self.manager.list_wallets("example.com")}
        self.assertIn("Savings", listed)  # it IS in the list output

        result = self.manager.delete_wallet("Savings")
        self.assertTrue(result["ok"])
        self.assertEqual(result["drained_sats"], 12)
        self.assertEqual(self._hub.deleted, [listed["Savings"]["pubkey"]])

    def test_delete_cli_by_name_exit_zero(self) -> None:
        with redirect_stdout(io.StringIO()):
            rc = cli_mod.main(["delete", "Shop Till"])
        self.assertEqual(rc, 0, "CLI delete by name should succeed")
        self.assertNotIn(2, self._hub.apps)

    def test_drain_by_name(self) -> None:
        result = self.manager.drain_wallet("Savings")
        self.assertTrue(result["ok"])
        self.assertEqual(result["drained_sats"], 12)

    def test_rotate_by_name(self) -> None:
        result = self.manager.rotate_wallet_secret("Car Fund")
        self.assertTrue(result["pairing_uri"])

    # -- other accepted identifiers -------------------------------------
    def test_delete_by_alias(self) -> None:
        self.assertTrue(self.manager.delete_wallet("savings")["ok"])

    def test_delete_by_id(self) -> None:
        self.assertTrue(self.manager.delete_wallet("1")["ok"])
        self.assertNotIn(1, self._hub.apps)

    def test_delete_by_pubkey(self) -> None:
        pubkey = self.manager.list_wallets("example.com")[0]["pubkey"]
        self.assertTrue(self.manager.delete_wallet(pubkey)["ok"])

    def test_delete_by_lightning_address(self) -> None:
        self.assertTrue(self.manager.delete_wallet("shop@example.com")["ok"])
        self.assertNotIn(2, self._hub.apps)

    def test_lookup_is_case_and_whitespace_insensitive(self) -> None:
        self.assertTrue(self.manager.delete_wallet("  sAvInGs  ")["ok"])

    # -- safety ----------------------------------------------------------
    def test_unmanaged_apps_are_not_deletable(self) -> None:
        with self.assertRaises(mgr_mod.AlbyHubError) as ctx:
            self.manager.delete_wallet("Decoy Unmanaged")
        self.assertEqual(ctx.exception.code, "wallet_not_found")
        self.assertEqual(self._hub.deleted, [])

    def test_empty_identifier(self) -> None:
        with self.assertRaises(mgr_mod.AlbyHubError) as ctx:
            self.manager.delete_wallet("   ")
        self.assertEqual(ctx.exception.code, "wallet_not_found")

    def test_ambiguous_identifier_rejected(self) -> None:
        # "savings" is the alias of app 1 *and* the name of this one.
        self._hub.apps[9] = make_app(9, "savings", "other-alias")
        with self.assertRaises(mgr_mod.AlbyHubError) as ctx:
            self.manager.delete_wallet("savings")
        self.assertEqual(ctx.exception.code, "wallet_ambiguous")
        self.assertEqual(self._hub.deleted, [])
        self.assertIn(1, self._hub.apps)
        self.assertIn(9, self._hub.apps)

    def test_audit_records_alias(self) -> None:
        with tempfile.NamedTemporaryFile("r", suffix=".log", delete=False) as fh:
            log_path = fh.name
        self.addCleanup(os.unlink, log_path)
        orig = mgr_mod._audit_mod.AUDIT_LOG_PATH
        mgr_mod._audit_mod.AUDIT_LOG_PATH = log_path
        self.addCleanup(setattr, mgr_mod._audit_mod, "LOG_PATH", orig)

        self.manager.delete_wallet("Savings")
        with open(log_path) as fh:
            entries = [json.loads(line) for line in fh if line.strip()]
        entry = next(e for e in entries if e["event"] == "wallet_deleted")
        self.assertEqual(entry["alias"], "savings")
        self.assertEqual(entry["name"], "Savings")

    def test_cli_list_still_shows_wallets(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_mod.main(["list"])
        payload = json.loads(buf.getvalue())
        self.assertEqual(rc, 0)
        self.assertEqual(len(payload["wallets"]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
