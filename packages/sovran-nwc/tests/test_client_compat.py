"""Client-compatibility tests for the NWC info advertisement.

BitBanana <= 1.1.x speaks NIP-47 through rust-nostr `nostr-sdk` 0.43, which
deserializes the `get_info` result into fixed structs:

  * `methods: Vec<String>` — unknown names parse fine, BUT the request side's
    `Method` enum is closed, so a client that mirrors the advertisement into
    that enum (or any client with a strict enum, e.g. rust-nostr's own
    `Method`) fails the whole response on one unknown name;
  * every other field is optional except `methods`.

`test_methods_only_contain_names_legacy_clients_know` pins the conservative
advertisement so a future extension cannot silently break those clients
again; `test_info_event_advertises_extensions_not_unknown_methods` keeps
discovery intact through the extensions tag.
"""

from __future__ import annotations

import os
import sys
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

import tempfile  # noqa: E402

from sovran_nwc import nwc_audit as audit_mod  # noqa: E402
from sovran_nwc import nwc_daemon as daemon_mod  # noqa: E402
from test_nwc_daemon import FakeLndClient  # noqa: E402

# The complete `Method` enum of rust-nostr 0.43 (BitBanana 1.1.1), plus the
# names NIP-47 defines today. Anything outside this set is not understood by
# every deployed client, so it must not appear in `get_info.methods` unless
# an operator opts in.
LEGACY_SAFE_METHODS = {
    "pay_invoice",
    "multi_pay_invoice",
    "pay_keysend",
    "multi_pay_keysend",
    "make_invoice",
    "lookup_invoice",
    "list_transactions",
    "get_balance",
    "get_info",
}


class ClientCompatibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._orig_audit_path = audit_mod.AUDIT_LOG_PATH
        audit_mod.AUDIT_LOG_PATH = os.path.join(self._tmpdir.name, "audit.log")
        self.addCleanup(setattr, audit_mod, "AUDIT_LOG_PATH", self._orig_audit_path)
        self._orig_advertise = daemon_mod.ADVERTISE_EXTENSION_METHODS
        self.addCleanup(
            setattr, daemon_mod, "ADVERTISE_EXTENSION_METHODS", self._orig_advertise
        )
        self.store = daemon_mod.NwcStore(":memory:")
        self.addCleanup(self.store.close)
        self.daemon = daemon_mod.SovranNwcDaemon(
            store=self.store, lnd=FakeLndClient(), unlock_password="pw", relays=[]
        )

    def _app(self, scopes=None):
        scopes = scopes or [
            "get_info", "get_balance", "make_invoice", "lookup_invoice",
            "list_transactions", "notifications", "pay_invoice", "get_budget",
        ]
        created = self.store.create_app(
            name="pocket", scopes=scopes, isolated=True, max_amount_sat=0,
            budget_renewal="never", metadata={}, relays=["wss://relay.example"],
        )
        return self.store.get_app_internal_by_pubkeys(
            created["appPubkey"], created["walletPubkey"]
        )

    def test_methods_only_contain_names_legacy_clients_know(self) -> None:
        info = self.daemon.handle_nip47_method(self._app(), "get_info", {})["result"]
        unknown = sorted(set(info["methods"]) - LEGACY_SAFE_METHODS)
        self.assertEqual(
            unknown, [],
            "get_info.methods advertises names unknown to rust-nostr 0.43 "
            "(BitBanana <= 1.1.x): a strict-enum client fails the whole "
            "get_info response and reports a dead connection. Discovery for "
            "extensions belongs in the `extensions` tag.",
        )

    def test_legacy_methods_still_answered(self) -> None:
        app = self._app()
        for method, params in (
            ("get_info", {}),
            ("get_balance", {}),
            ("list_transactions", {"type": "incoming", "unpaid": True,
                                   "from": None, "until": None,
                                   "limit": None, "offset": None}),
            ("make_invoice", {"amount": 21_000, "description": "x",
                              "description_hash": None, "expiry": 3600}),
        ):
            resp = self.daemon.handle_nip47_method(app, method, params)
            self.assertEqual(resp["result_type"], method)
            self.assertNotIn("error", resp, f"{method} must answer legacy clients")

    def test_lookup_payment_still_callable_but_not_advertised_by_default(self) -> None:
        app = self._app()
        info = self.daemon.handle_nip47_method(app, "get_info", {})["result"]
        self.assertNotIn("lookup_payment", info["methods"])
        # ...but a client that knows NWC-09 from the extensions tag can call it.
        self.assertIn("09", info["extensions"])
        resp = self.daemon.handle_nip47_method(
            app, "lookup_payment", {"payment_hash": "ab" * 32}
        )
        self.assertEqual(resp["result_type"], "lookup_payment")
        self.assertEqual(resp["error"]["code"], "NOT_FOUND")  # no such payment

    def test_opt_in_restores_full_advertisement(self) -> None:
        daemon_mod.ADVERTISE_EXTENSION_METHODS = True
        info = self.daemon.handle_nip47_method(self._app(), "get_info", {})["result"]
        self.assertIn("lookup_payment", info["methods"])
        self.assertIn("get_budget", info["methods"])

    def test_info_event_advertises_extensions_not_unknown_methods(self) -> None:
        app = self._app()
        info_ev = self.daemon.build_nip47_info_event(app)
        self.assertEqual(info_ev["kind"], 13194)
        tags = {t[0]: t[1] for t in info_ev["tags"] if len(t) >= 2}
        # Content is the method list clients read; extensions carry the rest.
        self.assertNotIn("lookup_payment", info_ev["content"].split())
        self.assertNotIn("get_budget", info_ev["content"].split())
        self.assertIn("09", tags.get("extensions", "").split())
        self.assertIn("13", tags.get("extensions", "").split())
        self.assertEqual(tags.get("encryption"), "nip44_v2 nip04")

    def test_info_event_opt_in(self) -> None:
        daemon_mod.ADVERTISE_EXTENSION_METHODS = True
        info_ev = self.daemon.build_nip47_info_event(self._app())
        self.assertIn("lookup_payment", info_ev["content"].split())
        self.assertIn("get_budget", info_ev["content"].split())


if __name__ == "__main__":
    unittest.main()
