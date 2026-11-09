"""Tests for NIP-42 relay authentication.

- `_nip42_authenticate` answers an AUTH challenge with a valid kind-22242
  event (relay + challenge tags, signed by the oldest wallet's key).
- Malformed challenges and wallet-less daemons send nothing.
- The relay loop end-to-end: an `auth-required` CLOSED is tolerated, the
  AUTH challenge is answered, and subscriptions are re-issued afterwards
  (the original REQ went out pre-auth and may have been refused).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
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
from sovran_nwc import nwc_nostr as nostr_mod  # noqa: E402
from test_nwc_daemon import FakeLndClient  # noqa: E402


class FakeConn:
    """Stand-in for WebSocketConnection recording everything sent."""

    def __init__(self, url="wss://relay.example", timeout=None, socks5_proxy=None,
                 frames=None):
        self.url = url
        self.sent: list = []
        self._frames = list(frames or [])
        self.closed = False

    def connect(self) -> None:
        pass

    def send_json(self, obj) -> None:
        self.sent.append(obj)

    def recv_message(self):
        if self._frames:
            return json.dumps(self._frames.pop(0))
        time.sleep(0.01)
        return None

    def close(self) -> None:
        self.closed = True


class Nip42AuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._orig_audit_path = audit_mod.AUDIT_LOG_PATH
        audit_mod.AUDIT_LOG_PATH = os.path.join(self._tmpdir.name, "audit.log")
        self.addCleanup(setattr, audit_mod, "AUDIT_LOG_PATH", self._orig_audit_path)
        self.store = daemon_mod.NwcStore(":memory:")
        self.addCleanup(self.store.close)
        self.daemon = daemon_mod.SovranNwcDaemon(
            store=self.store, lnd=FakeLndClient(), unlock_password="pw", relays=[]
        )
        self.app = self.store.create_app(
            name="pocket",
            scopes=["get_info"],
            isolated=True,
            max_amount_sat=0,
            budget_renewal="never",
            metadata={},
            relays=[],
        )

    def test_auth_event_is_valid_kind_22242(self) -> None:
        conn = FakeConn()
        ok = self.daemon._nip42_authenticate(conn, "wss://relay.example", "chal-123")
        self.assertTrue(ok)
        self.assertEqual(len(conn.sent), 1)
        frame = conn.sent[0]
        self.assertEqual(frame[0], "AUTH")
        ev = frame[1]
        self.assertEqual(ev["kind"], 22242)
        self.assertEqual(ev["pubkey"], self.app["walletPubkey"])
        self.assertIn(["relay", "wss://relay.example"], ev["tags"])
        self.assertIn(["challenge", "chal-123"], ev["tags"])
        self.assertTrue(nostr_mod.verify_event(ev))

    def test_auth_uses_oldest_wallet(self) -> None:
        second = self.store.create_app(
            name="second",
            scopes=["get_info"],
            isolated=True,
            max_amount_sat=0,
            budget_renewal="never",
            metadata={},
            relays=[],
        )
        conn = FakeConn()
        self.assertTrue(
            self.daemon._nip42_authenticate(conn, "wss://relay.example", "c")
        )
        self.assertEqual(conn.sent[0][1]["pubkey"], self.app["walletPubkey"])
        self.assertNotEqual(conn.sent[0][1]["pubkey"], second["walletPubkey"])

    def test_malformed_challenges_send_nothing(self) -> None:
        for bad in (None, "", 123, ["x"], "x" * 2000):
            conn = FakeConn()
            self.assertFalse(
                self.daemon._nip42_authenticate(conn, "wss://relay.example", bad)
            )
            self.assertEqual(conn.sent, [])

    def test_no_wallets_no_auth(self) -> None:
        empty_store = daemon_mod.NwcStore(":memory:")
        self.addCleanup(empty_store.close)
        daemon = daemon_mod.SovranNwcDaemon(
            store=empty_store, lnd=FakeLndClient(), unlock_password="pw", relays=[]
        )
        conn = FakeConn()
        self.assertFalse(daemon._nip42_authenticate(conn, "wss://relay.example", "c"))
        self.assertEqual(conn.sent, [])

    def test_relay_loop_authenticates_and_resubscribes(self) -> None:
        frames = [
            ["CLOSED", "sovran-nwc-sub", "auth-required: we can't serve DMs to unauthenticated users"],
            ["AUTH", "loop-challenge"],
        ]
        created: list[FakeConn] = []

        def factory(url, timeout=None, socks5_proxy=None):
            conn = FakeConn(url, timeout, socks5_proxy, frames=frames)
            created.append(conn)
            return conn

        original = daemon_mod._nostr_mod.WebSocketConnection
        daemon_mod._nostr_mod.WebSocketConnection = factory
        self.addCleanup(
            setattr, daemon_mod._nostr_mod, "WebSocketConnection", original
        )
        thread = threading.Thread(
            target=self.daemon._relay_loop,
            args=("wss://relay.example",),
            daemon=True,
        )
        thread.start()
        deadline = time.time() + 10
        conn = None
        while time.time() < deadline:
            if created:
                conn = created[0]
                if any(f[0] == "AUTH" for f in conn.sent):
                    break
            time.sleep(0.02)
        self.daemon.stop()
        thread.join(timeout=5)
        self.assertIsNotNone(conn)
        auth_frames = [f for f in conn.sent if f[0] == "AUTH"]
        self.assertEqual(len(auth_frames), 1)
        self.assertEqual(auth_frames[0][1]["kind"], 22242)
        self.assertIn(["challenge", "loop-challenge"], auth_frames[0][1]["tags"])
        reqs = [f for f in conn.sent if f[0] == "REQ"]
        self.assertGreaterEqual(
            len(reqs), 2, "subscription must be re-issued after authentication"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
