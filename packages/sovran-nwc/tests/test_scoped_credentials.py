"""Scoped-credential tests for the daemon management API.

The scope of a token must be decided by *which credential* is presented to
`/api/unlock`, never by the `permission` the caller asks for:

  - the unlock password may mint any scope (including lesser ones)
  - an invoice/read scoped credential may mint only its own scope; asking
    for more is a 403, and the public LNURL service therefore cannot turn
    its secret into full ledger authority
  - the unlock response reports the permission actually granted
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import types
import unittest

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if "sovran_nwc" not in sys.modules:
    _pkg = types.ModuleType("sovran_nwc")
    _pkg.__path__ = [_PKG_ROOT]  # type: ignore[attr-defined]
    sys.modules["sovran_nwc"] = _pkg
for _p in (_PKG_ROOT, os.path.join(_PKG_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from sovran_nwc import nwc_audit as audit_mod  # noqa: E402
from sovran_nwc import nwc_daemon as daemon_mod  # noqa: E402
from sovran_nwc import nwc_hub_manager as mgr_mod  # noqa: E402
from test_nwc_daemon import FakeLndClient  # noqa: E402
from test_wallet_lookup import _loopback_usable  # noqa: E402

FULL_PW = "operator-unlock-password"
INVOICE_PW = "lnurl-scoped-secret"
READ_PW = "monitor-scoped-secret"


class ScopedCredentialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self._orig_audit_path = audit_mod.AUDIT_LOG_PATH
        audit_mod.AUDIT_LOG_PATH = os.path.join(self.tmpdir.name, "audit.log")
        self.addCleanup(setattr, audit_mod, "AUDIT_LOG_PATH", self._orig_audit_path)

        self.store = daemon_mod.NwcStore(os.path.join(self.tmpdir.name, "nwc.db"))
        self.addCleanup(self.store.close)
        self.lnd = FakeLndClient()
        self.daemon = daemon_mod.SovranNwcDaemon(
            store=self.store,
            lnd=self.lnd,
            unlock_password=FULL_PW,
            relays=[],
            scoped_passwords={"invoice": INVOICE_PW, "read": READ_PW},
        )
        self.app = self.store.create_app(
            name="pocket",
            scopes=["get_info", "make_invoice"],
            isolated=True,
            max_amount_sat=0,
            budget_renewal="never",
            metadata={"lnurl_alias": "pocket"},
            relays=[],
        )

    # ── helpers ────────────────────────────────────────────────────

    def _unlock(self, password: str, permission: str | None = None):
        body: dict = {"unlockPassword": password}
        if permission is not None:
            body["permission"] = permission
        return self.daemon.handle_http("POST", "/api/unlock", {}, body)

    def _bearer(self, password: str, permission: str) -> dict:
        status, body = self._unlock(password, permission)
        self.assertEqual(status, 200, body)
        return {"Authorization": "Bearer " + body["token"]}

    # ── scoped credential behaviour ────────────────────────────────

    def test_invoice_credential_mints_invoice_token(self) -> None:
        status, body = self._unlock(INVOICE_PW, "invoice")
        self.assertEqual(status, 200)
        self.assertEqual(body["permission"], "invoice")

    def test_invoice_credential_cannot_escalate_to_full(self) -> None:
        status, body = self._unlock(INVOICE_PW, "full")
        self.assertEqual(status, 403)
        self.assertEqual(body["code"], "forbidden")
        self.assertNotIn("token", body)

    def test_invoice_credential_default_request_is_full_and_refused(self) -> None:
        # No permission field == requesting the default ("full"): a scoped
        # credential must refuse loudly, never silently upgrade or downgrade.
        status, _body = self._unlock(INVOICE_PW)
        self.assertEqual(status, 403)

    def test_read_credential_cannot_mint_invoice(self) -> None:
        status, _body = self._unlock(READ_PW, "invoice")
        self.assertEqual(status, 403)
        status, body = self._unlock(READ_PW, "read")
        self.assertEqual(status, 200)
        self.assertEqual(body["permission"], "read")

    def test_wrong_password_is_401(self) -> None:
        status, _body = self._unlock("not-any-credential", "invoice")
        self.assertEqual(status, 401)

    def test_invoice_token_reaches_only_invoice_endpoints(self) -> None:
        headers = self._bearer(INVOICE_PW, "invoice")
        # Alias resolution view (sanitized) — allowed.
        status, body = self.daemon.handle_http("GET", "/api/apps", headers, None)
        self.assertEqual(status, 200)
        self.assertNotIn("balanceMsat", str(body))
        # Invoice issuance — allowed.
        status, _body = self.daemon.handle_http(
            "POST",
            "/api/invoices",
            headers,
            {"amountMsat": 5000, "toAppId": int(self.app["id"]), "description": "tip"},
        )
        self.assertEqual(status, 200)
        # Admin / money-movement endpoints — forbidden.
        status, _ = self.daemon.handle_http(
            "POST",
            "/api/transfers",
            headers,
            {"amountMsat": 1000, "toAppId": int(self.app["id"])},
        )
        self.assertEqual(status, 403)
        status, _ = self.daemon.handle_http("POST", "/api/apps", headers, {"name": "x"})
        self.assertEqual(status, 403)
        status, _ = self.daemon.handle_http(
            "GET", "/api/transactions", headers, None
        )
        self.assertEqual(status, 403)

    # ── unlock password behaviour (unchanged authority, honest grants) ─

    def test_unlock_password_mints_full(self) -> None:
        headers = self._bearer(FULL_PW, "full")
        status, _ = self.daemon.handle_http(
            "POST",
            "/api/transfers",
            headers,
            {"amountMsat": 1000, "toAppId": int(self.app["id"])},
        )
        self.assertEqual(status, 200)

    def test_unlock_password_can_mint_lesser_scope(self) -> None:
        status, body = self._unlock(FULL_PW, "invoice")
        self.assertEqual(status, 200)
        self.assertEqual(body["permission"], "invoice")
        headers = {"Authorization": "Bearer " + body["token"]}
        status, _ = self.daemon.handle_http(
            "POST", "/api/transfers", headers, {"amountMsat": 1000}
        )
        self.assertEqual(status, 403)

    def test_response_reports_granted_not_requested(self) -> None:
        # Unknown permission string must not be echoed back as if granted.
        status, body = self._unlock(FULL_PW, "bogus-scope")
        self.assertEqual(status, 200)
        self.assertEqual(body["permission"], "full")

    def test_scoped_secret_equal_to_unlock_password_is_ignored(self) -> None:
        daemon = daemon_mod.SovranNwcDaemon(
            store=self.store,
            lnd=self.lnd,
            unlock_password=FULL_PW,
            relays=[],
            scoped_passwords={"invoice": FULL_PW},
        )
        self.assertEqual(daemon._scoped_passwords, {})
        # The shared secret is the unlock password, so it keeps full power —
        # the point is that no *distinct* invoice credential exists.
        token = daemon.issue_token(FULL_PW, "full")
        self.assertTrue(token)


@unittest.skipUnless(_loopback_usable(), "loopback sockets unavailable")
class ScopedCredentialManagerIntegrationTest(unittest.TestCase):
    """End-to-end: AlbyHubManager (as used by nwc-lnurl) against a live daemon."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self._orig_audit_path = audit_mod.AUDIT_LOG_PATH
        audit_mod.AUDIT_LOG_PATH = os.path.join(self.tmpdir.name, "audit.log")
        self.addCleanup(setattr, audit_mod, "AUDIT_LOG_PATH", self._orig_audit_path)

        self.store = daemon_mod.NwcStore(os.path.join(self.tmpdir.name, "nwc.db"))
        self.addCleanup(self.store.close)
        self.daemon = daemon_mod.SovranNwcDaemon(
            store=self.store,
            lnd=FakeLndClient(),
            unlock_password=FULL_PW,
            relays=[],
            scoped_passwords={"invoice": INVOICE_PW},
        )
        self.server = daemon_mod.make_http_server("127.0.0.1", 0, self.daemon)
        threading.Thread(
            target=self.server.serve_forever, args=(0.02,), daemon=True
        ).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        host, port = self.server.server_address[:2]
        self.api_base = f"http://{host}:{port}"

        self.mac_file = os.path.join(self.tmpdir.name, "macaroon")
        with open(self.mac_file, "wb") as fh:
            fh.write(b"\x01\x02")

        self.app = self.store.create_app(
            name="pocket",
            scopes=["get_info", "make_invoice"],
            isolated=True,
            max_amount_sat=0,
            budget_renewal="never",
            metadata={"lnurl_alias": "pocket"},
            relays=[],
        )

    def _manager(self, password: str, permission: str) -> mgr_mod.AlbyHubManager:
        pw_file = os.path.join(self.tmpdir.name, f"pw-{permission}")
        with open(pw_file, "w") as fh:
            fh.write(password + "\n")
        return mgr_mod.AlbyHubManager(
            api_base=self.api_base,
            unlock_password_file=pw_file,
            macaroon_file=self.mac_file,
            permission=permission,
        )

    def test_lnurl_style_manager_works_with_scoped_secret(self) -> None:
        manager = self._manager(INVOICE_PW, "invoice")
        bolt11 = manager.issue_invoice(int(self.app["id"]), 5000, "tip")
        self.assertTrue(bolt11.startswith("lnbcrt"))

    def test_lnurl_style_manager_cannot_obtain_full_with_scoped_secret(self) -> None:
        manager = self._manager(INVOICE_PW, "full")
        with self.assertRaises(mgr_mod.AlbyHubError):
            manager.issue_invoice(int(self.app["id"]), 5000, "tip")


if __name__ == "__main__":
    unittest.main(verbosity=2)
