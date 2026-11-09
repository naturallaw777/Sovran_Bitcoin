"""Tests for NWC-13 `get_budget` and NWC-09 `lookup_payment`.

- get_budget: empty result when unconfigured (distinct from a zero budget),
  used/total for the "never" period, calendar-period windows for renewing
  budgets, its own scope (independent of get_balance), advertised via
  get_info + the extensions tag.
- lookup_payment: lookup by transaction_id / payment_hash / invoice, the
  NWC-09 record envelope, per-connection visibility (another wallet's record
  is NOT_FOUND, never revealed), BAD_REQUEST on conflicting selectors,
  MULTIPLE_MATCHES for a self-payment, UNSUPPORTED_PAYMENT_TYPE, and the
  rule that a preimage is only disclosed when it hashes to the payment hash.
"""

from __future__ import annotations

import os
import sys
import time
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
from test_nwc_daemon import FakeLndClient  # noqa: E402
import tempfile  # noqa: E402

ALL_SCOPES = [
    "get_info",
    "get_balance",
    "make_invoice",
    "lookup_invoice",
    "list_transactions",
    "notifications",
    "pay_invoice",
    "get_budget",
]


class BudgetAndLookupTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._orig_audit_path = audit_mod.AUDIT_LOG_PATH
        audit_mod.AUDIT_LOG_PATH = os.path.join(self._tmpdir.name, "audit.log")
        self.addCleanup(setattr, audit_mod, "AUDIT_LOG_PATH", self._orig_audit_path)
        self.store = daemon_mod.NwcStore(":memory:")
        self.addCleanup(self.store.close)
        self.lnd = FakeLndClient()
        self.daemon = daemon_mod.SovranNwcDaemon(
            store=self.store, lnd=self.lnd, unlock_password="pw", relays=[]
        )

    # ── helpers ────────────────────────────────────────────────────

    def _app(self, name="pocket", scopes=None, max_sat=0, renewal="never", fund=0):
        created = self.store.create_app(
            name=name,
            scopes=scopes if scopes is not None else ALL_SCOPES,
            isolated=True,
            max_amount_sat=max_sat,
            budget_renewal=renewal,
            metadata={"lnurl_alias": name},
            relays=[],
        )
        app = self.store.get_app(int(created["id"]))
        if fund:
            self.store.transfer(
                from_app_id=None, to_app_id=int(app["id"]), amount_msat=fund
            )
            app = self.store.get_app(int(app["id"]))
        return app

    def _call(self, app, method, params=None):
        return self.daemon.handle_nip47_method(app, method, params or {})

    # ── get_budget ─────────────────────────────────────────────────

    def test_get_budget_empty_when_unconfigured(self) -> None:
        app = self._app(max_sat=0)
        resp = self._call(app, "get_budget")
        self.assertEqual(resp["result"], {})

    def test_get_budget_never_period(self) -> None:
        app = self._app(max_sat=100, fund=200_000)  # 100 sat budget
        pay = self._call(app, "pay_invoice", {"invoice": "lnbcrt10ext_budget"})
        self.assertIn("result", pay)
        resp = self._call(app, "get_budget")
        result = resp["result"]
        self.assertEqual(result["total_budget"], 100_000)
        # 10,000 msat payment + 1,500 msat fake fee, settled.
        self.assertEqual(result["used_budget"], 11_500)
        self.assertEqual(result["renewal_period"], "never")
        self.assertNotIn("renews_at", result)

    def test_get_budget_monthly_window_excludes_last_month(self) -> None:
        app = self._app(max_sat=50, renewal="monthly", fund=200_000)
        old_ts = int(time.time()) - 40 * 86400
        with self.store._lock:
            self.store._conn.execute(
                """
                INSERT INTO sovran_transactions (
                    app_id, type, state, amount_msat, fees_paid_msat,
                    fee_reserve_msat, payment_hash, invoice, preimage,
                    description, description_hash, created_at, settled_at
                ) VALUES (?, 'outgoing', 'settled', 7000, 0, 0, ?, '', '', '', '', ?, ?)
                """,
                (int(app["id"]), "ab" * 32, old_ts, old_ts),
            )
            self.store._conn.commit()
        resp = self._call(app, "get_budget")
        result = resp["result"]
        self.assertEqual(result["renewal_period"], "monthly")
        self.assertEqual(result["used_budget"], 0)
        self.assertGreater(result["renews_at"], int(time.time()))

    def test_get_budget_has_independent_scope(self) -> None:
        app = self._app(scopes=["get_budget"], max_sat=10)
        self.assertIn("result", self._call(app, "get_budget"))
        no_scope = self._app(name="noscope", scopes=["get_balance"], max_sat=10)
        resp = self._call(no_scope, "get_budget")
        self.assertEqual(resp["error"]["code"], "RESTRICTED")

    def test_get_info_advertises_new_methods_and_extensions(self) -> None:
        app = self._app()
        info = self._call(app, "get_info")["result"]
        # `get_budget` and `lookup_payment` are deliberately withheld from
        # `methods` by default:
        # rust-nostr 0.43 (the NWC client in BitBanana <= 1.1.x) deserializes
        # `methods` into a closed enum, so one unknown name breaks get_info
        # for that whole class of clients. NWC-09 discovery happens through
        # the extensions tag; the method itself stays callable.
        self.assertNotIn("lookup_payment", info["methods"])
        self.assertNotIn("get_budget", info["methods"])
        self.assertIn("lookup_payment", daemon_mod.ALL_KNOWN_NIP47_METHODS)
        self.assertEqual(
            self._call(app, "lookup_payment", {"payment_hash": "ab" * 32})["result_type"],
            "lookup_payment",
        )
        self.assertIn("13", info["extensions"])
        self.assertIn("09", info["extensions"])

    def test_get_info_can_advertise_lookup_payment_again(self) -> None:
        orig = daemon_mod.ADVERTISE_EXTENSION_METHODS
        daemon_mod.ADVERTISE_EXTENSION_METHODS = True
        self.addCleanup(setattr, daemon_mod, "ADVERTISE_EXTENSION_METHODS", orig)
        app = self._app()
        info = self._call(app, "get_info")["result"]
        self.assertIn("lookup_payment", info["methods"])
        self.assertIn("get_budget", info["methods"])

    # ── lookup_payment ─────────────────────────────────────────────

    def _make_invoice(self, app, amount=5000):
        resp = self._call(app, "make_invoice", {"amount": amount, "description": "x"})
        self.assertIn("result", resp)
        return resp["result"]

    def test_lookup_by_hash_invoice_and_transaction_id(self) -> None:
        app = self._app(fund=100_000)
        inv = self._make_invoice(app)
        by_hash = self._call(
            app, "lookup_payment", {"payment_hash": inv["payment_hash"]}
        )["result"]
        self.assertEqual(by_hash["type"], "incoming")
        self.assertEqual(by_hash["state"], "pending")
        self.assertEqual(by_hash["payment_type"], "bolt11")
        self.assertEqual(by_hash["amount"], 5000)
        self.assertEqual(by_hash["details"]["payment_hash"], inv["payment_hash"])
        self.assertEqual(by_hash["details"]["invoice"], inv["invoice"])

        by_invoice = self._call(app, "lookup_payment", {"invoice": inv["invoice"]})[
            "result"
        ]
        self.assertEqual(by_invoice["transaction_id"], by_hash["transaction_id"])

        by_id = self._call(
            app, "lookup_payment", {"transaction_id": inv["transaction_id"]}
        )["result"]
        self.assertEqual(by_id["transaction_id"], by_hash["transaction_id"])

    def test_lookup_outgoing_and_preimage_guard(self) -> None:
        app = self._app(fund=200_000)
        pay = self._call(app, "pay_invoice", {"invoice": "lnbcrt10ext_lookup"})
        self.assertIn("result", pay)
        txs, _ = self.store.list_transactions(app_id=int(app["id"]), unpaid=True)
        outgoing = [t for t in txs if t["type"] == "outgoing"][0]
        result = self._call(
            app, "lookup_payment", {"payment_hash": outgoing["paymentHash"]}
        )["result"]
        self.assertEqual(result["type"], "outgoing")
        self.assertEqual(result["state"], "settled")
        self.assertEqual(result["fees_paid"], 1500)
        # The fake's returned preimage does not hash to the invoice's payment
        # hash, so NWC-09 forbids disclosing it as this payment's preimage.
        self.assertNotIn("preimage", result["details"])

    def test_lookup_does_not_reveal_other_wallets_records(self) -> None:
        owner = self._app(name="owner", fund=100_000)
        stranger = self._app(name="stranger", fund=100_000)
        inv = self._make_invoice(owner)
        resp = self._call(
            stranger, "lookup_payment", {"payment_hash": inv["payment_hash"]}
        )
        self.assertEqual(resp["error"]["code"], "NOT_FOUND")
        resp = self._call(
            stranger, "lookup_payment", {"transaction_id": inv["transaction_id"]}
        )
        self.assertEqual(resp["error"]["code"], "NOT_FOUND")

    def test_lookup_selector_errors(self) -> None:
        app = self._app(fund=100_000)
        inv_a = self._make_invoice(app, 5000)
        inv_b = self._make_invoice(app, 6000)
        resp = self._call(app, "lookup_payment", {})
        self.assertEqual(resp["error"]["code"], "BAD_REQUEST")
        resp = self._call(
            app,
            "lookup_payment",
            {"payment_hash": inv_a["payment_hash"], "invoice": inv_b["invoice"]},
        )
        self.assertEqual(resp["error"]["code"], "BAD_REQUEST")
        resp = self._call(
            app, "lookup_payment", {"payment_type": "bolt12", "lookup": {}}
        )
        self.assertEqual(resp["error"]["code"], "UNSUPPORTED_PAYMENT_TYPE")
        resp = self._call(app, "lookup_payment", {"payment_hash": "cd" * 32})
        self.assertEqual(resp["error"]["code"], "NOT_FOUND")
        resp = self._call(app, "lookup_payment", {"transaction_id": "not-a-number"})
        self.assertEqual(resp["error"]["code"], "BAD_REQUEST")

    def test_lookup_self_payment_is_multiple_matches(self) -> None:
        app = self._app(fund=100_000)
        inv = self._make_invoice(app, 8000)
        pay = self._call(app, "pay_invoice", {"invoice": inv["invoice"]})
        self.assertIn("result", pay)
        resp = self._call(
            app, "lookup_payment", {"payment_hash": inv["payment_hash"]}
        )
        self.assertEqual(resp["error"]["code"], "MULTIPLE_MATCHES")
        # ...while each row remains individually addressable by id.
        txs, _ = self.store.list_transactions(app_id=int(app["id"]), unpaid=True)
        for tx in txs:
            one = self._call(
                app, "lookup_payment", {"transaction_id": str(tx["id"])}
            )
            self.assertIn("result", one)


if __name__ == "__main__":
    unittest.main(verbosity=2)
