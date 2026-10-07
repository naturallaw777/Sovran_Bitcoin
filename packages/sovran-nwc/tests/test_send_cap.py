"""Tests for the NWC send-cap fix.

Regression test for: "wallet has 30,000 sats, tries to spend 12,000, gets 'the
wallet does not have enough budget remaining to make this payment'".

Alby Hub gates a send on two unrelated numbers
(transactions/transactions_service.go -> validateCanPay):

    balance : balance_msat        >= amount + fee_reserve
    budget  : maxAmountSat - used >= (amount + fee_reserve)/1000   (if maxAmountSat > 0)

maxAmountSat is cumulative and never renews (apps are created with
budgetRenewal="never"), and sats received after creation raise the balance but
not the cap. An isolated wallet cannot spend more than it holds anyway, so
create_wallet no longer sets a cap.

Run with:  python3 tests/test_send_cap.py
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

from sovran_nwc import nwc_hub_manager as mgr_mod  # noqa: E402
from test_wallet_lookup import FakeHub, _loopback_usable, build_manager  # noqa: E402


class SendCapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not _loopback_usable():
            raise unittest.SkipTest("loopback sockets unavailable (sandboxed build?)")

    def setUp(self) -> None:
        self.hub = FakeHub([]).__enter__()
        self.addCleanup(self.hub.__exit__)
        self.manager = build_manager(self.hub)

    def test_create_funds_the_wallet_without_setting_a_cap(self) -> None:
        """--limit-sats is the funding amount; maxAmountSat stays 0."""
        result = self.manager.create_wallet(
            "pocket", "pocket", "send_receive_limited", 30_000, "example.com"
        )
        created = self.hub.created[-1]
        self.assertEqual(created["maxAmountSat"], 0)
        self.assertTrue(created["isolated"])
        # funded, so the balance alone is the limit
        self.assertEqual(self.hub.apps[created["id"]]["balanceMsat"], 30_000_000)
        # ...and reported, not 0
        self.assertEqual(result["wallet"]["balance_sats"], 30_000)
        self.assertIsNone(result["wallet"]["spending_limit_sats"])

    def test_receive_only_is_unchanged(self) -> None:
        self.manager.create_wallet("recv", "recv", "receive_only", None, "example.com")
        created = self.hub.created[-1]
        self.assertEqual(created["maxAmountSat"], 0)
        self.assertNotIn("pay_invoice", created["scopes"])
        self.assertEqual(self.hub.transfers, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
