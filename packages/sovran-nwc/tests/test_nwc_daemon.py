"""End-to-end tests for the native Sovran NWC Daemon (REST API, SQLite ledger, NIP-47)."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import tempfile
import threading
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

from sovran_nwc import nwc_daemon as daemon_mod  # noqa: E402
from sovran_nwc import nwc_hub_manager as mgr_mod  # noqa: E402
from sovran_nwc import nwc_lnd as lnd_mod  # noqa: E402
from sovran_nwc import nwc_nostr as nostr_mod  # noqa: E402
from test_wallet_lookup import _loopback_usable  # noqa: E402


class FakeLndClient(lnd_mod.LndRestClient):
    """In-memory mock of LndRestClient for deterministic unit testing."""

    def __init__(self) -> None:
        super().__init__(rest_url="https://127.0.0.1:8080")
        self.channel_balance_msat = 500_000_000  # 500,000 sats
        self.invoices: dict[str, dict[str, Any]] = {}
        self.created_invoices: list[dict[str, Any]] = []
        self.next_payment_error: str | None = None
        self.next_fee_msat: int = 1_500

    def get_info(self) -> dict[str, Any]:
        return {
            "pubkey": "02" + "aa" * 32,
            "alias": "sovran-regtest",
            "color": "#ff9900",
            "block_height": 850000,
            "block_hash": "00" * 32,
            "network": "regtest",
            "synced_to_chain": True,
        }

    def get_channel_balance_msat(self) -> int:
        return self.channel_balance_msat

    def create_invoice(
        self,
        amount_msat: int,
        memo: str = "",
        expiry: int = 3600,
        description_hash_hex: str | None = None,
        private: bool = True,
    ) -> dict[str, Any]:
        preimage = secrets.token_bytes(32)
        payment_hash = hashlib.sha256(preimage).hexdigest()
        now = int(time.time())
        bolt11 = f"lnbcrt{amount_msat}n1p{payment_hash[:16]}"
        inv = {
            "invoice": bolt11,
            "payment_hash": payment_hash,
            "preimage": preimage.hex(),
            "amount_msat": int(amount_msat),
            "description": memo or "",
            "description_hash": (description_hash_hex or "").lower(),
            "created_at": now,
            "expires_at": now + int(expiry),
            "settled_at": None,
            "state": "pending",
            "private": private,
        }
        self.invoices[payment_hash] = inv
        self.invoices[bolt11] = inv
        self.created_invoices.append(inv)
        return dict(inv)

    def lookup_invoice(self, payment_hash_hex: str) -> dict[str, Any]:
        inv = self.invoices.get(payment_hash_hex.lower())
        if inv is None:
            raise lnd_mod.LndError("NOT_FOUND", "Invoice not found")
        return dict(inv)

    def decode_payreq(self, bolt11: str) -> dict[str, Any]:
        inv = self.invoices.get(bolt11)
        if inv is not None:
            return {
                "destination": "03" + "bb" * 32,
                "payment_hash": inv["payment_hash"],
                "amount_msat": inv["amount_msat"],
                "timestamp": inv["created_at"],
                "expiry": 3600,
                "expires_at": inv["expires_at"],
                "description": inv["description"],
                "description_hash": inv["description_hash"],
            }
        # External invoice encoding convention: lnbcrt<sats>ext_<id>
        import re
        m = re.match(r"^lnbcrt(\d+)ext", bolt11)
        amt_msat = int(m.group(1)) * 1000 if m else 5_000_000
        ph = hashlib.sha256(bolt11.encode("utf-8")).hexdigest()
        return {
            "destination": "03" + "cc" * 32,
            "payment_hash": ph,
            "amount_msat": amt_msat,
            "timestamp": int(time.time()),
            "expiry": 3600,
            "expires_at": int(time.time()) + 3600,
            "description": "External payment",
            "description_hash": "",
        }

    def pay_invoice(
        self,
        bolt11: str,
        fee_limit_msat: int,
        amount_msat: int | None = None,
    ) -> dict[str, Any]:
        if self.next_payment_error:
            err = self.next_payment_error
            self.next_payment_error = None
            raise lnd_mod.LndPaymentError(err)
        preimage = secrets.token_bytes(32)
        ph = hashlib.sha256(preimage).hexdigest()
        return {
            "preimage": preimage.hex(),
            "payment_hash": ph,
            "fees_paid_msat": self.next_fee_msat,
        }


class SovranNwcDaemonTest(unittest.TestCase):
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

        self._orig_audit = _audit_path = mgr_mod._audit_mod.AUDIT_LOG_PATH
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
        threading.Thread(
            target=self.server.serve_forever, args=(0.02,), daemon=True
        ).start()
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

    def test_full_wallet_lifecycle_and_private_invoices(self) -> None:
        # 1. Health check
        health = self.manager.health()
        self.assertTrue(health["ok"])
        self.assertTrue(health["hub_ready"])

        # 2. Create funded wallet (20,000 sats)
        created = self.manager.create_wallet(
            "Mobile Wallet", "mobile", "send_receive_limited", 20_000, "pay.example.com"
        )
        self.assertTrue(created["pairing_uri"].startswith("nostr+walletconnect://"))
        self.assertEqual(created["wallet"]["balance_sats"], 20_000)
        self.assertEqual(created["wallet"]["lightning_address"], "mobile@pay.example.com")
        app_id = int(created["wallet"]["id"])

        # 3. Issue invoice via LNURL / manager and verify private=True route hints
        bolt11 = self.manager.issue_invoice(app_id, 3_000_000, "Coffee")
        self.assertTrue(bolt11.startswith("lnbcrt"))
        self.assertTrue(self.lnd.created_invoices[-1]["private"])

        # 4. Simulate LND settling the invoice; verify balance increases to 23,000 sats
        ph = self.lnd.created_invoices[-1]["payment_hash"]
        self.lnd.invoices[ph]["state"] = "settled"
        self.lnd.invoices[ph]["settled_at"] = int(time.time())

        wallets = self.manager.list_wallets("pay.example.com")
        self.assertEqual(len(wallets), 1)
        self.assertEqual(wallets[0]["balance_sats"], 23_000)

        # 5. Drain and delete wallet
        del_res = self.manager.delete_wallet("Mobile Wallet")
        self.assertTrue(del_res["ok"])
        self.assertEqual(del_res["drained_sats"], 23_000)
        self.assertEqual(self.manager.list_wallets("pay.example.com"), [])

    def test_least_privilege_invoice_token_blocks_admin_actions(self) -> None:
        # Create a receive-only wallet using the full admin manager
        created = self.manager.create_wallet(
            "Tip Jar", "tips", "receive_only", None, "pay.example.com"
        )
        app_id = int(created["wallet"]["id"])

        # Create a scoped "invoice" manager (used by nwc-lnurl)
        lnurl_manager = mgr_mod.AlbyHubManager(
            api_base=self.api_base,
            unlock_password_file=self.pw_file,
            macaroon_file=self.mac_file,
            permission="invoice",
        )

        # Allowed: alias lookup + invoice creation
        app = lnurl_manager.find_app_by_alias("tips")
        self.assertIsNotNone(app)
        bolt11 = lnurl_manager.issue_invoice(app_id, 5_000_000, "LNURL tip")
        self.assertTrue(bolt11.startswith("lnbcrt"))

        # Forbidden: creating wallets, deleting wallets, draining/transferring funds
        with self.assertRaises(mgr_mod.AlbyHubHttpError) as ctx:
            lnurl_manager.create_wallet("Evil", "evil", "send_receive_limited", 1000, None)
        self.assertEqual(ctx.exception.status_code, 403)

        with self.assertRaises(mgr_mod.AlbyHubHttpError) as ctx2:
            lnurl_manager._authenticated_request(
                "POST", "/api/transfers", body={"toAppId": app_id, "amountSat": 50000}
            )
        self.assertEqual(ctx2.exception.status_code, 403)

    def test_nip47_encrypted_requests_and_payments(self) -> None:
        # Create a funded wallet and a receive-only wallet
        w_send = self.manager.create_wallet(
            "Spender", "spender", "send_receive_limited", 10_000, "pay.example.com"
        )
        w_recv = self.manager.create_wallet(
            "Receiver", "receiver", "receive_only", None, "pay.example.com"
        )

        # Parse pairing URIs
        def parse_uri(uri: str) -> tuple[str, str]:
            body = uri.split("nostr+walletconnect://", 1)[1]
            wallet_pub, qs = body.split("?", 1)
            secret = [
                kv.split("=", 1)[1]
                for kv in qs.split("&")
                if kv.startswith("secret=")
            ][0]
            return wallet_pub, secret

        send_wpub, send_sec = parse_uri(w_send["pairing_uri"])
        recv_wpub, recv_sec = parse_uri(w_recv["pairing_uri"])

        def call_nip47(
            client_sec_hex: str,
            wallet_pub_hex: str,
            method: str,
            params: dict[str, Any],
            use_nip44: bool = True,
        ) -> dict[str, Any]:
            c_priv = bytes.fromhex(client_sec_hex)
            w_pub = bytes.fromhex(wallet_pub_hex)
            plaintext = json.dumps({"method": method, "params": params})
            if use_nip44:
                enc = nostr_mod.nip44_encrypt(plaintext, c_priv, w_pub)
                tags = [["p", wallet_pub_hex], ["encryption", "nip44_v2"]]
            else:
                enc = nostr_mod.nip04_encrypt(plaintext, c_priv, w_pub)
                tags = [["p", wallet_pub_hex]]
            ev = nostr_mod.make_event(client_sec_hex, kind=23194, content=enc, tags=tags)
            resps = self.daemon.process_nip47_event(ev)
            self.assertEqual(len(resps), 1)
            resp_ev = resps[0]
            self.assertTrue(nostr_mod.verify_event(resp_ev))
            if use_nip44:
                dec = nostr_mod.nip44_decrypt(resp_ev["content"], c_priv, w_pub)
            else:
                dec = nostr_mod.nip04_decrypt(resp_ev["content"], c_priv, w_pub)
            return json.loads(dec)

        # 1. get_balance via NIP-44 v2
        bal_resp = call_nip47(send_sec, send_wpub, "get_balance", {}, use_nip44=True)
        self.assertEqual(bal_resp["result"]["balance"], 10_000_000)

        # 2. get_info via NIP-04
        info_resp = call_nip47(send_sec, send_wpub, "get_info", {}, use_nip44=False)
        self.assertEqual(info_resp["result"]["network"], "regtest")

        # 3. Receive-only wallet cannot pay_invoice
        denied = call_nip47(
            recv_sec, recv_wpub, "pay_invoice", {"invoice": "lnbcrt5000ext_1"}
        )
        self.assertEqual(denied["error"]["code"], "RESTRICTED")

        # 4. External payment from Spender (5,000 sats + 1,500 msat routing fee)
        self.lnd.next_fee_msat = 1_500
        pay_resp = call_nip47(
            send_sec, send_wpub, "pay_invoice", {"invoice": "lnbcrt5000ext_1"}
        )
        self.assertIn("preimage", pay_resp["result"])
        self.assertEqual(pay_resp["result"]["fees_paid"], 1_500)

        # Balance should be 10,000,000 - 5,000,000 - 1,500 = 4,998,500 msat
        bal_after = call_nip47(send_sec, send_wpub, "get_balance", {})
        self.assertEqual(bal_after["result"]["balance"], 4_998_500)

        # 5. Failed external payment refunds full reserve
        self.lnd.next_payment_error = "no_route"
        fail_resp = call_nip47(
            send_sec, send_wpub, "pay_invoice", {"invoice": "lnbcrt1000ext_fail"}
        )
        self.assertEqual(fail_resp["error"]["code"], "PAYMENT_FAILED")
        bal_refunded = call_nip47(send_sec, send_wpub, "get_balance", {})
        self.assertEqual(bal_refunded["result"]["balance"], 4_998_500)

        # 6. Internal self-payment: Receiver creates invoice for 2,000 sats, Spender pays it
        inv_resp = call_nip47(
            recv_sec,
            recv_wpub,
            "make_invoice",
            {"amount": 2_000_000, "description": "Internal transfer"},
        )
        internal_bolt11 = inv_resp["result"]["invoice"]

        self_pay = call_nip47(
            send_sec, send_wpub, "pay_invoice", {"invoice": internal_bolt11}
        )
        self.assertEqual(self_pay["result"]["fees_paid"], 0)

        # Receiver now has 2,000,000 msat; Spender has 2,998,500 msat
        recv_bal = call_nip47(recv_sec, recv_wpub, "get_balance", {})
        send_bal = call_nip47(send_sec, send_wpub, "get_balance", {})
        self.assertEqual(recv_bal["result"]["balance"], 2_000_000)
        self.assertEqual(send_bal["result"]["balance"], 2_998_500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
