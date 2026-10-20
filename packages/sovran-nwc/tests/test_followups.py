"""Tests for the NWC follow-up fixes.

1. The deprecated `multi_pay_*` commands are no longer advertised or
   handled — they answer NOT_IMPLEMENTED (they were removed from NIP-47 and
   only existed as an Alby Hub legacy dialect).
2. Internal self-payments return the real payment preimage (verifiable with
   sha256(preimage) == payment_hash) instead of a fabricated placeholder.
3. `pay_keysend` (NWC-04) works for spend-capable wallets and stays
   RESTRICTED for receive-only wallets.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import tempfile
import threading
import types
import unittest
from typing import Any
from urllib.parse import parse_qs, urlsplit

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if "sovran_nwc" not in sys.modules:
    _pkg = types.ModuleType("sovran_nwc")
    _pkg.__path__ = [_PKG_ROOT]  # type: ignore[attr-defined]
    sys.modules["sovran_nwc"] = _pkg
for _p in (_PKG_ROOT, os.path.join(_PKG_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from sovran_nwc import nwc_daemon as daemon_mod  # noqa: E402
from sovran_nwc import nwc_hub_manager as mgr_mod  # noqa: E402
from sovran_nwc import nwc_nostr as nostr_mod  # noqa: E402
from test_nwc_daemon import FakeLndClient  # noqa: E402
from test_wallet_lookup import _loopback_usable  # noqa: E402


def _parse_uri(uri: str) -> tuple[str, str]:
    body = uri.split("nostr+walletconnect://", 1)[1]
    wallet_pub, qs = body.split("?", 1)
    secret = [
        kv.split("=", 1)[1] for kv in qs.split("&") if kv.startswith("secret=")
    ][0]
    return wallet_pub, secret


class FollowupsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not _loopback_usable():
            raise unittest.SkipTest("loopback sockets unavailable")

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.db_path = os.path.join(self.tmpdir.name, "nwc.db")
        self.pw_file = os.path.join(self.tmpdir.name, "unlock-password")
        self.mac_file = os.path.join(self.tmpdir.name, "albyhub.macaroon")
        self.audit_file = os.path.join(self.tmpdir.name, "audit.log")

        with open(self.pw_file, "w") as f:
            f.write("super-secret-password\n")
        with open(self.mac_file, "wb") as f:
            f.write(b"\x01\x02\x03\x04")

        self._orig_audit = mgr_mod._audit_mod.AUDIT_LOG_PATH
        mgr_mod._audit_mod.AUDIT_LOG_PATH = self.audit_file
        self.addCleanup(setattr, mgr_mod._audit_mod, "AUDIT_LOG_PATH", self._orig_audit)

        self.store = daemon_mod.NwcStore(self.db_path)
        self.addCleanup(self.store.close)
        self.lnd = FakeLndClient()
        self.daemon = daemon_mod.SovranNwcDaemon(
            store=self.store,
            lnd=self.lnd,
            unlock_password="super-secret-password",
            relays=["wss://relay.example.com"],
        )
        self.server = daemon_mod.make_http_server("127.0.0.1", 0, self.daemon)
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.daemon.stop)

        host, port = self.server.server_address[:2]
        self.api_base = f"http://{host}:{port}"
        self.manager = mgr_mod.AlbyHubManager(
            api_base=self.api_base,
            unlock_password_file=self.pw_file,
            macaroon_file=self.mac_file,
            permission="full",
        )

    # ── helpers ────────────────────────────────────────────────────

    def _create_wallet(
        self,
        name: str,
        balance_sats: int | None,
        preset: str = "send_receive_limited",
    ):
        created = self.manager.create_wallet(
            name, name.lower(), preset, balance_sats, "pay.example.com"
        )
        wpub, sec = _parse_uri(created["pairing_uri"])
        return int(created["wallet"]["id"]), wpub, sec

    def _call(self, client_sec: str, wpub: str, method: str, params: dict[str, Any],
              use_nip44: bool = True) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Returns [(response_payload, response_event), ...]."""
        c_priv = bytes.fromhex(client_sec)
        w_pub = bytes.fromhex(wpub)
        plaintext = json.dumps({"method": method, "params": params})
        if use_nip44:
            enc = nostr_mod.nip44_encrypt(plaintext, c_priv, w_pub)
            tags = [["p", wpub], ["encryption", "nip44_v2"]]
        else:
            enc = nostr_mod.nip04_encrypt(plaintext, c_priv, w_pub)
            tags = [["p", wpub]]
        ev = nostr_mod.make_event(client_sec, kind=23194, content=enc, tags=tags)
        resps = self.daemon.process_nip47_event(ev)
        out = []
        for resp_ev in resps:
            self.assertTrue(nostr_mod.verify_event(resp_ev))
            if use_nip44:
                dec = nostr_mod.nip44_decrypt(resp_ev["content"], c_priv, w_pub)
            else:
                dec = nostr_mod.nip04_decrypt(resp_ev["content"], c_priv, w_pub)
            out.append((json.loads(dec), resp_ev))
        return out

    def _call1(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        resps = self._call(*args, **kwargs)
        self.assertEqual(len(resps), 1)
        return resps[0][0]

    # ── fix 2: internal payments carry the real preimage ───────────

    def test_internal_payment_returns_real_preimage(self) -> None:
        recv_id, recv_wpub, recv_sec = self._create_wallet("Receiver", 5_000)
        send_id, send_wpub, send_sec = self._create_wallet("Sender", 10_000)

        inv = self._call1(
            recv_sec, recv_wpub, "make_invoice",
            {"amount": 2_000_000, "description": "Internal transfer"},
        )["result"]
        payment_hash = inv["payment_hash"]
        real_preimage = self.lnd.invoices[payment_hash]["preimage"]

        paid = self._call1(send_sec, send_wpub, "pay_invoice", {"invoice": inv["invoice"]})
        self.assertNotIn("error", paid, paid)
        preimage = paid["result"]["preimage"]
        # Verifiable preimage — NEVER the old sha256(payment_hash) placeholder.
        self.assertEqual(preimage, real_preimage)
        self.assertEqual(hashlib.sha256(bytes.fromhex(preimage)).hexdigest(), payment_hash)
        self.assertEqual(paid["result"]["fees_paid"], 0)

        # Both ledger rows carry the real preimage.
        out_tx = self.store.find_tx_for_app(send_id, payment_hash=payment_hash)
        in_tx = self.store.find_tx_for_app(recv_id, payment_hash=payment_hash)
        self.assertEqual(out_tx["preimage"], real_preimage)
        self.assertEqual(in_tx["preimage"], real_preimage)

    def test_internal_payment_resolves_legacy_rows_without_preimage(self) -> None:
        # Rows created before preimages were stored have preimage = "".
        recv_id, recv_wpub, recv_sec = self._create_wallet("Receiver", 5_000)
        send_id, send_wpub, send_sec = self._create_wallet("Sender", 10_000)

        inv = self._call1(
            recv_sec, recv_wpub, "make_invoice",
            {"amount": 1_000_000, "description": "Legacy row"},
        )["result"]
        payment_hash = inv["payment_hash"]
        real_preimage = self.lnd.invoices[payment_hash]["preimage"]

        # Simulate a legacy ledger: wipe the stored preimages.
        with self.store._lock:
            self.store._conn.execute(
                "UPDATE sovran_transactions SET preimage = '' WHERE payment_hash = ?",
                (payment_hash,),
            )

        paid = self._call1(send_sec, send_wpub, "pay_invoice", {"invoice": inv["invoice"]})
        self.assertNotIn("error", paid, paid)
        preimage = paid["result"]["preimage"]
        self.assertEqual(preimage, real_preimage)
        self.assertEqual(hashlib.sha256(bytes.fromhex(preimage)).hexdigest(), payment_hash)

        # Resolved and recorded on both rows for later lookups.
        out_tx = self.store.find_tx_for_app(send_id, payment_hash=payment_hash)
        in_tx = self.store.find_tx_for_app(recv_id, payment_hash=payment_hash)
        self.assertEqual(out_tx["preimage"], real_preimage)
        self.assertEqual(in_tx["preimage"], real_preimage)

    # ── fix 1: deprecated multi_pay_* are no longer offered ────────

    def test_multi_pay_commands_answer_not_implemented(self) -> None:
        # Removed from NIP-47 (Alby Hub legacy dialect only) — the daemon
        # answers NOT_IMPLEMENTED instead of advertising-but-failing.
        _, wpub, sec = self._create_wallet("Spender", 10_000)
        resps = self._call(
            sec, wpub, "multi_pay_invoice",
            {"invoices": [{"id": "a1", "invoice": "lnbcrt1000ext_x"}]},
        )
        self.assertEqual(len(resps), 1)
        payload = resps[0][0]
        self.assertEqual(payload["error"]["code"], "NOT_IMPLEMENTED", payload)

        resps = self._call(
            sec, wpub, "multi_pay_keysend",
            {"keysends": [{"amount": 1, "pubkey": "02" + "aa" * 32}]},
        )
        self.assertEqual(resps[0][0]["error"]["code"], "NOT_IMPLEMENTED")

        # No payments were attempted and no balance moved.
        bal = self._call1(sec, wpub, "get_balance", {})["result"]["balance"]
        self.assertEqual(bal, 10_000_000)

    def test_unknown_methods_answer_not_implemented_not_restricted(self) -> None:
        _, wpub, sec = self._create_wallet("Spender", 10_000)
        res = self._call1(sec, wpub, "sign_message", {"message": "hi"})
        self.assertEqual(res["error"]["code"], "NOT_IMPLEMENTED")

    # ── fix 3: pay_keysend (NWC-04) ────────────────────────────────

    def test_pay_keysend_success_and_real_preimage(self) -> None:
        app_id, wpub, sec = self._create_wallet("Spender", 10_000)
        self.lnd.next_fee_msat = 750
        dest = "02" + "ab" * 32

        # Without a client-supplied preimage one is generated and echoed back.
        res = self._call1(
            sec, wpub, "pay_keysend",
            {"amount": 500_000, "pubkey": dest},
        )
        self.assertNotIn("error", res, res)
        preimage = res["result"]["preimage"]
        self.assertEqual(len(preimage), 64)
        self.assertEqual(res["result"]["fees_paid"], 750)
        self.assertEqual(self.lnd.keysends[-1]["dest"], dest)
        self.assertEqual(self.lnd.keysends[-1]["amount_msat"], 500_000)
        self.assertEqual(self.lnd.keysends[-1]["preimage"], preimage)
        # Ledger payment hash matches sha256(preimage).
        ph = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        tx = self.store.find_tx_for_app(app_id, payment_hash=ph)
        self.assertIsNotNone(tx)
        self.assertEqual(tx["preimage"], preimage)

        # With an explicit preimage it is honored end-to-end.
        my_preimage = secrets.token_bytes(32).hex()
        res2 = self._call1(
            sec, wpub, "pay_keysend",
            {
                "amount": 100_000,
                "pubkey": dest,
                "preimage": my_preimage,
                "tlv_records": [{"type": 696969, "value": "cafe"}],
            },
        )
        self.assertEqual(res2["result"]["preimage"], my_preimage)
        recs = self.lnd.keysends[-1]["tlv_records"]
        self.assertEqual(recs[0]["type"], 696969)
        self.assertEqual(recs[0]["value"], "cafe")

        # Balance: 10,000,000 − 500,000 − 750 − 100,000 − 750
        bal = self._call1(sec, wpub, "get_balance", {})["result"]["balance"]
        self.assertEqual(bal, 10_000_000 - 500_000 - 750 - 100_000 - 750)

    def test_pay_keysend_restricted_and_insufficient_balance(self) -> None:
        _, ro_wpub, ro_sec = self._create_wallet("ReadOnly", 5_000, preset="receive_only")
        res = self._call1(
            ro_sec, ro_wpub, "pay_keysend", {"amount": 1, "pubkey": "02" + "aa" * 32}
        )
        self.assertEqual(res["error"]["code"], "RESTRICTED")

        _, wpub, sec = self._create_wallet("Spender", 1_000)
        res = self._call1(
            sec, wpub, "pay_keysend",
            {"amount": 999_999_999, "pubkey": "02" + "aa" * 32},
        )
        self.assertEqual(res["error"]["code"], "INSUFFICIENT_BALANCE")
        # Failed reservation must not leak balance.
        bal = self._call1(sec, wpub, "get_balance", {})["result"]["balance"]
        self.assertEqual(bal, 1_000_000)

    def test_get_info_advertises_keysend_per_scope(self) -> None:
        _, wpub, sec = self._create_wallet("Spender", 10_000)
        info = self._call1(sec, wpub, "get_info", {})["result"]
        self.assertIn("pay_keysend", info["methods"])
        self.assertIn("pay_invoice", info["methods"])
        # The deprecated multi_* commands are not advertised at all.
        self.assertNotIn("multi_pay_invoice", info["methods"])
        self.assertNotIn("multi_pay_keysend", info["methods"])

        _, ro_wpub, ro_sec = self._create_wallet("ReadOnly", 5_000, preset="receive_only")
        info = self._call1(ro_sec, ro_wpub, "get_info", {})["result"]
        self.assertNotIn("pay_keysend", info["methods"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
