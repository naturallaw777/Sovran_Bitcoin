"""Invoice-lifecycle tests: expiry sweep, LND cancellation, pending cap, batching.

Covers the lifecycle that pending invoices previously never had:

  - an invoice still OPEN in LND past its BOLT11 expiry is canceled on LND
    and only then marked `expired` in the ledger
  - a settlement racing the expiry sweep always wins (credit, no cancel)
  - an LND-canceled invoice is closed in the ledger
  - after an internal wallet-to-wallet settlement the LND invoice is
    canceled, so it cannot be paid again externally and double-credited
  - a per-wallet pending cap refuses new invoices (QUOTA_EXCEEDED) before
    any LND invoice is created, and capacity returns after expiry
  - reconciliation batches through ListInvoices instead of one
    LookupInvoice per pending row
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import types
import unittest
from typing import Any

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
from sovran_nwc import nwc_lnd as lnd_mod  # noqa: E402
from test_nwc_daemon import FakeLndClient  # noqa: E402

SCOPES = [
    "get_info",
    "get_balance",
    "make_invoice",
    "lookup_invoice",
    "list_transactions",
    "notifications",
    "pay_invoice",
]


class LifecycleFakeLnd(FakeLndClient):
    """FakeLndClient plus the lifecycle endpoints, with call counters."""

    def __init__(self) -> None:
        super().__init__()
        self.cancelled: list[str] = []
        self.lookup_calls = 0
        self.list_calls = 0

    @staticmethod
    def _public(inv: dict[str, Any]) -> dict[str, Any]:
        out = dict(inv)
        # Mirror LndRestClient's normalization (CANCELED -> "failed").
        if out.get("state") == "canceled":
            out["state"] = "failed"
        return out

    def lookup_invoice(self, payment_hash_hex: str) -> dict[str, Any]:
        self.lookup_calls += 1
        inv = self.invoices.get(payment_hash_hex.lower())
        if inv is None:
            raise lnd_mod.LndError("NOT_FOUND", "Invoice not found")
        return self._public(inv)

    def list_invoices(
        self,
        num_max_invoices: int = 100,
        index_offset: int = 0,
        pending_only: bool = False,
        reversed: bool = False,
    ) -> dict[str, Any]:
        self.list_calls += 1
        uniq: dict[str, dict[str, Any]] = {}
        for inv in self.invoices.values():
            uniq[inv["payment_hash"]] = inv
        page = [self._public(i) for i in uniq.values()]
        return {
            "invoices": page,
            "last_index_offset": len(page),
            "first_index_offset": 1 if page else 0,
        }

    def cancel_invoice(self, payment_hash_hex: str) -> dict[str, Any]:
        ph = payment_hash_hex.lower()
        inv = self.invoices.get(ph)
        if inv is None:
            raise lnd_mod.LndError("NOT_FOUND", "Invoice not found")
        inv["state"] = "canceled"
        self.cancelled.append(ph)
        return {}


class InvoiceLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._orig_audit_path = audit_mod.AUDIT_LOG_PATH
        audit_mod.AUDIT_LOG_PATH = os.path.join(self._tmpdir.name, "audit.log")
        self.addCleanup(setattr, audit_mod, "AUDIT_LOG_PATH", self._orig_audit_path)
        self.store = daemon_mod.NwcStore(":memory:")
        self.addCleanup(self.store.close)
        self.lnd = LifecycleFakeLnd()
        self.daemon = daemon_mod.SovranNwcDaemon(
            store=self.store, lnd=self.lnd, unlock_password="pw", relays=[]
        )
        created = self.store.create_app(
            name="pocket",
            scopes=SCOPES,
            isolated=True,
            max_amount_sat=0,
            budget_renewal="never",
            metadata={"lnurl_alias": "pocket"},
            relays=[],
        )
        self.app = self.store.get_app(int(created["id"]))

    # ── helpers ────────────────────────────────────────────────────

    def _record(self, amount_msat: int = 5000, expires_at: int | None = None) -> dict:
        inv = self.lnd.create_invoice(amount_msat=amount_msat, memo="test", expiry=3600)
        if expires_at is not None:
            self.lnd.invoices[inv["payment_hash"]]["expires_at"] = expires_at
        return self.store.record_incoming_invoice(
            app_id=int(self.app["id"]),
            payment_hash=inv["payment_hash"],
            invoice=inv["invoice"],
            amount_msat=amount_msat,
            description="test",
            description_hash="",
            created_at=inv["created_at"],
            expires_at=expires_at if expires_at is not None else inv["expires_at"],
        )

    def _tx(self, payment_hash: str) -> dict | None:
        return self.store.find_tx_for_app(int(self.app["id"]), payment_hash=payment_hash)

    def _balance(self) -> int:
        return int(self.store.get_app(int(self.app["id"]))["balanceMsat"])

    # ── expiry sweep ───────────────────────────────────────────────

    def test_expired_invoice_is_canceled_on_lnd_then_expired(self) -> None:
        tx = self._record(expires_at=int(time.time()) - 10)
        self.daemon.reconcile_pending_invoices()
        self.assertEqual(self._tx(tx["paymentHash"])["state"], "expired")
        self.assertEqual(self.lnd.cancelled, [tx["paymentHash"]])
        self.assertEqual(self._balance(), 0)
        self.assertEqual(self.store.pending_incoming_count(int(self.app["id"])), 0)

    def test_unexpired_invoice_is_left_pending(self) -> None:
        tx = self._record(expires_at=int(time.time()) + 3600)
        self.daemon.reconcile_pending_invoices()
        self.assertEqual(self._tx(tx["paymentHash"])["state"], "pending")
        self.assertEqual(self.lnd.cancelled, [])

    def test_settlement_racing_expiry_wins(self) -> None:
        tx = self._record(amount_msat=7000, expires_at=int(time.time()) - 10)
        inv = self.lnd.invoices[tx["paymentHash"]]
        inv["state"] = "settled"
        inv["settled_at"] = int(time.time())
        self.daemon.reconcile_pending_invoices()
        settled = self._tx(tx["paymentHash"])
        self.assertEqual(settled["state"], "settled")
        self.assertEqual(self._balance(), 7000)
        self.assertEqual(self.lnd.cancelled, [])

    def test_lnd_canceled_invoice_is_closed(self) -> None:
        tx = self._record(expires_at=int(time.time()) + 3600)
        self.lnd.invoices[tx["paymentHash"]]["state"] = "canceled"
        self.daemon.reconcile_pending_invoices()
        self.assertEqual(self._tx(tx["paymentHash"])["state"], "expired")

    def test_unknown_invoice_state_retries_next_sweep(self) -> None:
        tx = self._record(expires_at=int(time.time()) - 10)
        del self.lnd.invoices[tx["paymentHash"]]
        del self.lnd.invoices[tx["invoice"]]
        self.daemon.reconcile_pending_invoices()
        # LND did not report it: never expire on a guess.
        self.assertEqual(self._tx(tx["paymentHash"])["state"], "pending")

    # ── batching ───────────────────────────────────────────────────

    def test_reconcile_batches_via_list_invoices(self) -> None:
        txs = [self._record() for _ in range(5)]
        winner = txs[2]
        inv = self.lnd.invoices[winner["paymentHash"]]
        inv["state"] = "settled"
        inv["settled_at"] = int(time.time())
        self.daemon.reconcile_pending_invoices()
        self.assertGreaterEqual(self.lnd.list_calls, 1)
        self.assertEqual(self.lnd.lookup_calls, 0)
        self.assertEqual(self._tx(winner["paymentHash"])["state"], "settled")
        self.assertEqual(self._balance(), 5000)
        for tx in txs:
            if tx["paymentHash"] != winner["paymentHash"]:
                self.assertEqual(self._tx(tx["paymentHash"])["state"], "pending")

    # ── pending cap ────────────────────────────────────────────────

    def test_pending_cap_refuses_before_creating_on_lnd(self) -> None:
        orig = daemon_mod.MAX_PENDING_INVOICES_PER_WALLET
        daemon_mod.MAX_PENDING_INVOICES_PER_WALLET = 2
        self.addCleanup(setattr, daemon_mod, "MAX_PENDING_INVOICES_PER_WALLET", orig)
        r1 = self.daemon.handle_nip47_method(self.app, "make_invoice", {"amount": 1000})
        r2 = self.daemon.handle_nip47_method(self.app, "make_invoice", {"amount": 1000})
        self.assertIn("result", r1)
        self.assertIn("result", r2)
        created_before = len(self.lnd.created_invoices)
        r3 = self.daemon.handle_nip47_method(self.app, "make_invoice", {"amount": 1000})
        self.assertEqual(r3["error"]["code"], "QUOTA_EXCEEDED")
        # Refused *before* an LND invoice was created: no orphan on LND.
        self.assertEqual(len(self.lnd.created_invoices), created_before)

    def test_pending_cap_recovers_after_expiry(self) -> None:
        orig = daemon_mod.MAX_PENDING_INVOICES_PER_WALLET
        daemon_mod.MAX_PENDING_INVOICES_PER_WALLET = 1
        self.addCleanup(setattr, daemon_mod, "MAX_PENDING_INVOICES_PER_WALLET", orig)
        self._record(expires_at=int(time.time()) - 5)
        with self.assertRaises(daemon_mod.NwcStoreError) as ctx:
            self._record()
        self.assertEqual(ctx.exception.code, "QUOTA_EXCEEDED")
        self.daemon.reconcile_pending_invoices()  # sweeps the expired one
        tx = self._record()
        self.assertEqual(tx["state"], "pending")

    def test_http_invoice_endpoint_returns_429_at_cap(self) -> None:
        orig = daemon_mod.MAX_PENDING_INVOICES_PER_WALLET
        daemon_mod.MAX_PENDING_INVOICES_PER_WALLET = 1
        self.addCleanup(setattr, daemon_mod, "MAX_PENDING_INVOICES_PER_WALLET", orig)
        self._record()
        token = self.daemon.issue_token("pw", "full")
        status, body = self.daemon.handle_http(
            "POST",
            "/api/invoices",
            {"Authorization": "Bearer " + token},
            {"amountMsat": 5000, "toAppId": int(self.app["id"])},
        )
        self.assertEqual(status, 429)
        self.assertEqual(body["code"], "QUOTA_EXCEEDED")

    # ── internal settlement cancels the LND invoice ────────────────

    def test_internal_settlement_cancels_lnd_invoice(self) -> None:
        payee = self.store.create_app(
            name="shop",
            scopes=SCOPES,
            isolated=True,
            max_amount_sat=0,
            budget_renewal="never",
            metadata={"lnurl_alias": "shop"},
            relays=[],
        )
        payee = self.store.get_app(int(payee["id"]))
        self.store.transfer(
            from_app_id=None, to_app_id=int(self.app["id"]), amount_msat=50_000
        )
        inv_resp = self.daemon.handle_nip47_method(
            payee, "make_invoice", {"amount": 8000, "description": "coffee"}
        )
        bolt11 = inv_resp["result"]["invoice"]
        ph = inv_resp["result"]["payment_hash"]
        pay_resp = self.daemon.handle_nip47_method(
            self.app, "pay_invoice", {"invoice": bolt11}
        )
        self.assertIn("result", pay_resp)
        self.assertTrue(pay_resp["result"]["preimage"])
        # Canceled on LND, settled exactly once in the ledger.
        self.assertIn(ph, self.lnd.cancelled)
        payee_tx = self.store.find_tx_for_app(int(payee["id"]), payment_hash=ph)
        self.assertEqual(payee_tx["state"], "settled")
        self.assertEqual(int(self.store.get_app(int(payee["id"]))["balanceMsat"]), 8000)
        # A late reconcile must not credit the payee a second time.
        self.daemon.reconcile_pending_invoices()
        self.assertEqual(int(self.store.get_app(int(payee["id"]))["balanceMsat"]), 8000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
