"""Regression tests for NIP-47 request hardening.

Covers the request-validation boundary that a paired client (or a relay
replaying old signed events) can reach:

  - `expiration` tag is honoured and stale `created_at` is refused
  - per-connection rate limiting returns `RATE_LIMITED`
  - an unsupported `encryption` tag returns `UNSUPPORTED_ENCRYPTION`
  - malformed params yield a NIP-47 error, never an escaping exception
  - `list_transactions` honours `unpaid`
  - `get_info` reports the wallet pubkey, not the LND node identity key
  - the 13194 info event advertises NWC extensions
  - the management API answers 400 (not 500) for malformed parameters
"""

from __future__ import annotations

import json
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

from sovran_nwc import nwc_daemon as daemon_mod  # noqa: E402
from sovran_nwc import nwc_nostr as nostr_mod  # noqa: E402
from test_nwc_daemon import FakeLndClient  # noqa: E402

ALL_SCOPES = [
    "get_info",
    "get_balance",
    "make_invoice",
    "lookup_invoice",
    "list_transactions",
    "notifications",
    "pay_invoice",
]


class RequestHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = daemon_mod.NwcStore(":memory:")
        self.lnd = FakeLndClient()
        self.daemon = daemon_mod.SovranNwcDaemon(
            store=self.store, lnd=self.lnd, unlock_password="pw", relays=[]
        )
        created = self.store.create_app(
            name="pocket",
            scopes=ALL_SCOPES,
            isolated=True,
            max_amount_sat=0,
            budget_renewal="never",
            metadata={"lnurl_alias": "pocket"},
            relays=["wss://relay.example"],
        )
        self.client_priv = created["pairingUri"].split("secret=")[1]
        self.client_pub = nostr_mod.pubkey_from_privkey(
            bytes.fromhex(self.client_priv)
        ).hex()
        self.app = self.store.get_app_internal_by_pubkeys(
            self.client_pub, created["walletPubkey"]
        )
        self.store.transfer(
            from_app_id=None, to_app_id=self.app["id"], amount_msat=5_000_000
        )

    # ── helpers ────────────────────────────────────────────────────

    def _request(self, method: str, params: dict, tags=None, created_at=None):
        body = json.dumps({"method": method, "params": params})
        content = nostr_mod.nip44_encrypt(
            body,
            bytes.fromhex(self.client_priv),
            bytes.fromhex(self.app["walletPubkey"]),
        )
        event_tags = [["p", self.app["walletPubkey"]], ["encryption", "nip44_v2"]]
        event_tags.extend(tags or [])
        return nostr_mod.make_event(
            self.client_priv, 23194, content, event_tags, created_at=created_at
        )

    def _decode(self, event: dict) -> dict:
        plaintext = nostr_mod.nip44_decrypt(
            event["content"],
            bytes.fromhex(self.client_priv),
            bytes.fromhex(self.app["walletPubkey"]),
        )
        return json.loads(plaintext)

    def _call(self, method: str, params: dict) -> dict:
        responses = self.daemon.process_nip47_event(self._request(method, params))
        self.assertEqual(len(responses), 1)
        return self._decode(responses[0])

    # ── tests ──────────────────────────────────────────────────────

    def test_expired_request_is_ignored(self) -> None:
        event = self._request(
            "make_invoice",
            {"amount": 1000},
            tags=[["expiration", str(int(time.time()) - 60)]],
        )
        self.assertEqual(self.daemon.process_nip47_event(event), [])
        self.assertEqual(self.lnd.created_invoices, [])

    def test_future_expiration_is_executed(self) -> None:
        event = self._request(
            "make_invoice",
            {"amount": 1000},
            tags=[["expiration", str(int(time.time()) + 600)]],
        )
        self.assertEqual(len(self.daemon.process_nip47_event(event)), 1)
        self.assertEqual(len(self.lnd.created_invoices), 1)

    def test_stale_created_at_is_ignored(self) -> None:
        event = self._request(
            "make_invoice",
            {"amount": 1000},
            created_at=int(time.time()) - daemon_mod.REQUEST_MAX_AGE_SEC - 60,
        )
        self.assertEqual(self.daemon.process_nip47_event(event), [])
        self.assertEqual(self.lnd.created_invoices, [])

    def test_far_future_created_at_is_ignored(self) -> None:
        event = self._request(
            "make_invoice",
            {"amount": 1000},
            created_at=int(time.time()) + daemon_mod.REQUEST_MAX_FUTURE_SKEW_SEC + 60,
        )
        self.assertEqual(self.daemon.process_nip47_event(event), [])

    def test_rate_limit_returns_rate_limited(self) -> None:
        limit = daemon_mod.NIP47_RATE_LIMIT_PER_MIN
        responses = []
        for _ in range(limit + 1):
            responses.extend(
                self.daemon.process_nip47_event(
                    self._request("get_balance", {})
                )
            )
        self.assertEqual(len(responses), limit + 1)
        last = self._decode(responses[-1])
        self.assertEqual(last["error"]["code"], "RATE_LIMITED")

    def test_unsupported_encryption_tag(self) -> None:
        body = json.dumps({"method": "get_balance", "params": {}})
        content = nostr_mod.nip44_encrypt(
            body,
            bytes.fromhex(self.client_priv),
            bytes.fromhex(self.app["walletPubkey"]),
        )
        event = nostr_mod.make_event(
            self.client_priv,
            23194,
            content,
            [["p", self.app["walletPubkey"]], ["encryption", "nip99_v9"]],
        )
        responses = self.daemon.process_nip47_event(event)
        self.assertEqual(len(responses), 1)
        self.assertEqual(
            self._decode(responses[0])["error"]["code"], "UNSUPPORTED_ENCRYPTION"
        )

    def test_nip04_request_still_supported(self) -> None:
        body = json.dumps({"method": "get_balance", "params": {}})
        content = nostr_mod.nip04_encrypt(
            body,
            bytes.fromhex(self.client_priv),
            bytes.fromhex(self.app["walletPubkey"]),
        )
        event = nostr_mod.make_event(
            self.client_priv,
            23194,
            content,
            [["p", self.app["walletPubkey"]], ["encryption", "nip04"]],
        )
        responses = self.daemon.process_nip47_event(event)
        self.assertEqual(len(responses), 1)
        plaintext = nostr_mod.nip04_decrypt(
            responses[0]["content"],
            bytes.fromhex(self.client_priv),
            bytes.fromhex(self.app["walletPubkey"]),
        )
        self.assertEqual(json.loads(plaintext)["result_type"], "get_balance")

    def test_malformed_amount_returns_error_not_exception(self) -> None:
        payload = self._call("make_invoice", {"amount": "not-a-number"})
        self.assertIn("error", payload)
        self.assertEqual(payload["error"]["code"], "OTHER")

    def test_malformed_params_type_returns_error(self) -> None:
        body = json.dumps({"method": "list_transactions", "params": ["oops"]})
        content = nostr_mod.nip44_encrypt(
            body,
            bytes.fromhex(self.client_priv),
            bytes.fromhex(self.app["walletPubkey"]),
        )
        event = nostr_mod.make_event(
            self.client_priv,
            23194,
            content,
            [["p", self.app["walletPubkey"]], ["encryption", "nip44_v2"]],
        )
        responses = self.daemon.process_nip47_event(event)
        self.assertEqual(len(responses), 1)
        self.assertEqual(self._decode(responses[0])["result_type"], "list_transactions")

    def test_invoice_expiry_is_bounded(self) -> None:
        self._call("make_invoice", {"amount": 1000, "expiry": 2**31})
        created = self.lnd.created_invoices[-1]
        self.assertLessEqual(
            created["expires_at"] - created["created_at"],
            daemon_mod.MAX_INVOICE_EXPIRY_SEC,
        )

    def test_list_transactions_unpaid_filter(self) -> None:
        self._call("make_invoice", {"amount": 5000})
        settled = self._call("list_transactions", {"unpaid": False})
        with_unpaid = self._call("list_transactions", {"unpaid": True})
        self.assertTrue(
            all(tx["state"] == "settled" for tx in settled["result"]["transactions"])
        )
        self.assertTrue(
            any(tx["state"] == "pending" for tx in with_unpaid["result"]["transactions"])
        )

    def test_list_transactions_limit_is_bounded(self) -> None:
        for _ in range(3):
            self._call("make_invoice", {"amount": 1000})
        payload = self._call("list_transactions", {"limit": 10**9, "unpaid": True})
        self.assertLessEqual(len(payload["result"]["transactions"]), daemon_mod.MAX_PAGE_SIZE)

    def test_get_info_does_not_leak_node_pubkey(self) -> None:
        payload = self._call("get_info", {})
        node_pubkey = self.lnd.get_info()["pubkey"]
        self.assertNotEqual(payload["result"]["pubkey"], node_pubkey)
        # 33-byte compressed form of the wallet key: rust-nostr 0.43 types
        # get_info.pubkey as secp256k1::PublicKey, which rejects x-only keys.
        self.assertEqual(
            payload["result"]["pubkey"],
            "02" + self.app["walletPubkey"].lower(),
        )

    def test_info_event_advertises_extensions(self) -> None:
        info = self.daemon.build_nip47_info_event(self.app)
        tags = {t[0]: t[1] for t in info["tags"]}
        self.assertEqual(tags["encryption"], "nip44_v2 nip04")
        self.assertEqual(tags["extensions"], "02 04 05 09")
        self.assertIn("pay_keysend", info["content"])

    def test_events_for_unknown_wallets_skip_signature_verification(self) -> None:
        """A flood of junk events must not cost one Schnorr verify each."""
        body = json.dumps({"method": "get_balance", "params": {}})
        content = nostr_mod.nip44_encrypt(
            body,
            bytes.fromhex(self.client_priv),
            bytes.fromhex(self.app["walletPubkey"]),
        )
        stranger = nostr_mod.make_event(
            self.client_priv,
            23194,
            content,
            [["p", "cc" * 32], ["encryption", "nip44_v2"]],
        )
        original = nostr_mod.verify_event
        calls = {"n": 0}

        def counting(event):
            calls["n"] += 1
            return original(event)

        nostr_mod.verify_event = counting
        try:
            self.assertEqual(self.daemon.process_nip47_event(stranger), [])
            self.assertEqual(calls["n"], 0, "signature verified for an unknown wallet")
            # A real request for a served wallet must still be verified.
            self.assertEqual(
                len(self.daemon.process_nip47_event(self._request("get_balance", {}))), 1
            )
            self.assertEqual(calls["n"], 1)
        finally:
            nostr_mod.verify_event = original

    def test_management_api_malformed_params_are_400(self) -> None:
        token = self.daemon.issue_token("pw", "read")
        headers = {"Authorization": "Bearer " + token}
        status, body = self.daemon.handle_http(
            "GET", "/api/transactions?limit=abc", headers, None
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "invalid_parameter")

    def test_management_api_includes_pending_for_operator(self) -> None:
        self._call("make_invoice", {"amount": 4000})
        token = self.daemon.issue_token("pw", "read")
        status, body = self.daemon.handle_http(
            "GET",
            f"/api/transactions?appId={self.app['id']}",
            {"Authorization": "Bearer " + token},
            None,
        )
        self.assertEqual(status, 200)
        self.assertTrue(
            any(tx["state"] == "pending" for tx in body["transactions"]),
            "nwc-wallet drain/delete rely on seeing pending transactions",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
