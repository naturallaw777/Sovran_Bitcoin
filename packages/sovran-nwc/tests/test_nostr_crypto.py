"""Tests for pure-stdlib Nostr cryptography (BIP-340, NIP-04, NIP-44 v2, NIP-01)."""

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

from sovran_nwc import nwc_nostr as nostr  # noqa: E402


class NostrCryptoTest(unittest.TestCase):
    def test_bip340_official_vectors(self) -> None:
        # Official BIP-340 test vector 0
        seckey0 = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000003"
        )
        expected_pk0 = bytes.fromhex(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
        )
        aux0 = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        msg0 = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        expected_sig0 = bytes.fromhex(
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
        )
        self.assertEqual(nostr.pubkey_from_privkey(seckey0), expected_pk0)
        sig0 = nostr.schnorr_sign(msg0, seckey0, aux0)
        self.assertEqual(sig0, expected_sig0)
        self.assertTrue(nostr.schnorr_verify(msg0, expected_pk0, sig0))

        # Official BIP-340 test vector 1 (odd Y secret key)
        seckey1 = bytes.fromhex(
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
        )
        expected_pk1 = bytes.fromhex(
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
        )
        aux1 = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        msg1 = bytes.fromhex(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
        )
        expected_sig1 = bytes.fromhex(
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
            "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
        )
        self.assertEqual(nostr.pubkey_from_privkey(seckey1), expected_pk1)
        sig1 = nostr.schnorr_sign(msg1, seckey1, aux1)
        self.assertEqual(sig1, expected_sig1)
        self.assertTrue(nostr.schnorr_verify(msg1, expected_pk1, sig1))
        # Mutated message must fail verify
        self.assertFalse(nostr.schnorr_verify(msg0, expected_pk1, sig1))

    def test_nip44_v2_official_vectors(self) -> None:
        # Official NIP-44 v2 test vector 1: sec1 = 1, sec2 = 2
        sec1 = (1).to_bytes(32, "big")
        sec2 = (2).to_bytes(32, "big")
        pub1 = nostr.pubkey_from_privkey(sec1)
        pub2 = nostr.pubkey_from_privkey(sec2)

        expected_conv = bytes.fromhex(
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
        )
        conv_12 = nostr.nip44_conversation_key(sec1, pub2)
        conv_21 = nostr.nip44_conversation_key(sec2, pub1)
        self.assertEqual(conv_12, expected_conv)
        self.assertEqual(conv_21, expected_conv)

        nonce = (1).to_bytes(32, "big")
        expected_payload = (
            "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD3"
            "5uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
        )
        ct = nostr.nip44_encrypt("a", sec1, pub2, nonce=nonce)
        self.assertEqual(ct, expected_payload)
        pt = nostr.nip44_decrypt(ct, sec2, pub1)
        self.assertEqual(pt, "a")

        # Tampered ciphertext must fail MAC
        with self.assertRaises(ValueError):
            nostr.nip44_decrypt(ct[:-4] + "AAAA", sec2, pub1)

    def test_nip44_calc_padded_len_vectors(self) -> None:
        cases = [
            (1, 32),
            (32, 32),
            (33, 64),
            (64, 64),
            (65, 96),
            (192, 192),
            (193, 224),
            (384, 384),
            (385, 448),
            (512, 512),
            (513, 640),
        ]
        for unpadded, expected in cases:
            self.assertEqual(nostr.nip44_calc_padded_len(unpadded), expected)

    def test_nip04_roundtrip(self) -> None:
        sec_a = (7).to_bytes(32, "big")
        sec_b = (11).to_bytes(32, "big")
        pub_a = nostr.pubkey_from_privkey(sec_a)
        pub_b = nostr.pubkey_from_privkey(sec_b)

        msg = '{"method":"get_balance","params":{}}'
        enc = nostr.nip04_encrypt(msg, sec_a, pub_b)
        self.assertIn("?iv=", enc)
        dec = nostr.nip04_decrypt(enc, sec_b, pub_a)
        self.assertEqual(dec, msg)

    def test_nip01_event_sign_and_verify(self) -> None:
        priv = (42).to_bytes(32, "big").hex()
        ev = nostr.make_event(
            priv,
            kind=13194,
            content="get_info get_balance make_invoice pay_invoice",
            tags=[["encryption", "nip44_v2 nip04"]],
        )
        self.assertTrue(nostr.verify_event(ev))
        ev_bad = dict(ev, content="tampered")
        self.assertFalse(nostr.verify_event(ev_bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
