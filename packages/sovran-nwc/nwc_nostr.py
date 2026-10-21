"""Pure-stdlib Nostr cryptography and relay client for Sovran NWC.

Implements:
  - secp256k1 point arithmetic and ECDH shared secret (raw x-coordinate)
  - BIP-340 Schnorr key generation, signing, and verification (NIP-01)
  - NIP-04 encryption/decryption (AES-256-CBC + PKCS#7)
  - NIP-44 v2 encryption/decryption (HKDF-SHA256 + ChaCha20 + HMAC-SHA256)
  - RFC 6455 WebSocket client over TLS/TCP (with optional SOCKS5 proxy for .onion relays)

Requires only the Python 3 standard library.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from typing import Callable

logger = logging.getLogger(__name__)

# ── secp256k1 curve constants ─────────────────────────────────────

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Jacobian point representation: (X, Y, Z) where Z == 0 is the point at infinity.
_JacPoint = tuple[int, int, int]
_INF: _JacPoint = (0, 1, 0)
_G: _JacPoint = (_GX, _GY, 1)


def _jac_double(p: _JacPoint) -> _JacPoint:
    X1, Y1, Z1 = p
    if Z1 == 0 or Y1 == 0:
        return _INF
    Y1_sq = (Y1 * Y1) % _P
    S = (4 * X1 * Y1_sq) % _P
    M = (3 * X1 * X1) % _P  # a = 0 for secp256k1
    X3 = (M * M - 2 * S) % _P
    Y1_4 = (Y1_sq * Y1_sq) % _P
    Y3 = (M * (S - X3) - 8 * Y1_4) % _P
    Z3 = (2 * Y1 * Z1) % _P
    return (X3, Y3, Z3)


def _jac_add(p: _JacPoint, q: _JacPoint) -> _JacPoint:
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    if Z1 == 0:
        return q
    if Z2 == 0:
        return p
    Z1_sq = (Z1 * Z1) % _P
    Z2_sq = (Z2 * Z2) % _P
    U1 = (X1 * Z2_sq) % _P
    U2 = (X2 * Z1_sq) % _P
    S1 = (Y1 * Z2_sq * Z2) % _P
    S2 = (Y2 * Z1_sq * Z1) % _P
    if U1 == U2:
        if S1 != S2:
            return _INF
        return _jac_double(p)
    H = (U2 - U1) % _P
    R = (S2 - S1) % _P
    H_sq = (H * H) % _P
    H_cu = (H * H_sq) % _P
    U1_H_sq = (U1 * H_sq) % _P
    X3 = (R * R - H_cu - 2 * U1_H_sq) % _P
    Y3 = (R * (U1_H_sq - X3) - S1 * H_cu) % _P
    Z3 = (H * Z1 * Z2) % _P
    return (X3, Y3, Z3)


def _jac_mul(k: int, p: _JacPoint = _G) -> _JacPoint:
    k = k % _N
    if k == 0 or p[2] == 0:
        return _INF
    result = _INF
    addend = p
    while k:
        if k & 1:
            result = _jac_add(result, addend)
        addend = _jac_double(addend)
        k >>= 1
    return result


def _to_affine(p: _JacPoint) -> tuple[int, int] | None:
    X, Y, Z = p
    if Z == 0:
        return None
    z_inv = pow(Z, _P - 2, _P)
    z_inv2 = (z_inv * z_inv) % _P
    z_inv3 = (z_inv2 * z_inv) % _P
    return ((X * z_inv2) % _P, (Y * z_inv3) % _P)


def _lift_x(x: int) -> tuple[int, int] | None:
    if x <= 0 or x >= _P:
        return None
    c = (pow(x, 3, _P) + 7) % _P
    y = pow(c, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != c:
        return None
    if y & 1:
        y = _P - y
    return (x, y)


# ── BIP-340 Schnorr & secp256k1 ECDH ──────────────────────────────

_TAG_HASH_CACHE: dict[str, bytes] = {}


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_digest = _TAG_HASH_CACHE.get(tag)
    if tag_digest is None:
        tag_digest = hashlib.sha256(tag.encode("utf-8")).digest()
        _TAG_HASH_CACHE[tag] = tag_digest
    return hashlib.sha256(tag_digest + tag_digest + msg).digest()


def pubkey_from_privkey(privkey32: bytes) -> bytes:
    """Return 32-byte x-only public key for a 32-byte secret key (BIP-340)."""
    if len(privkey32) != 32:
        raise ValueError("Private key must be 32 bytes")
    d0 = int.from_bytes(privkey32, "big")
    if not (1 <= d0 < _N):
        raise ValueError("Private key scalar out of range")
    pt = _to_affine(_jac_mul(d0, _G))
    if pt is None:
        raise ValueError("Invalid public point")
    return pt[0].to_bytes(32, "big")


def schnorr_sign(
    msg32: bytes, privkey32: bytes, aux_rand32: bytes | None = None
) -> bytes:
    """Sign a 32-byte message with BIP-340 Schnorr."""
    if len(msg32) != 32:
        raise ValueError("Message must be 32 bytes")
    if len(privkey32) != 32:
        raise ValueError("Private key must be 32 bytes")
    if aux_rand32 is None:
        aux_rand32 = secrets.token_bytes(32)
    elif len(aux_rand32) != 32:
        raise ValueError("aux_rand must be 32 bytes")

    d0 = int.from_bytes(privkey32, "big")
    if not (1 <= d0 < _N):
        raise ValueError("Private key scalar out of range")
    P = _to_affine(_jac_mul(d0, _G))
    if P is None:
        raise ValueError("Point at infinity")
    px, py = P
    d = d0 if (py % 2 == 0) else (_N - d0)

    t = d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux_rand32), "big")
    px_bytes = px.to_bytes(32, "big")
    rand = tagged_hash("BIP0340/nonce", t.to_bytes(32, "big") + px_bytes + msg32)
    k0 = int.from_bytes(rand, "big") % _N
    if k0 == 0:
        raise ValueError("Zero nonce generated")

    R = _to_affine(_jac_mul(k0, _G))
    if R is None:
        raise ValueError("Nonce point at infinity")
    rx, ry = R
    k = k0 if (ry % 2 == 0) else (_N - k0)
    rx_bytes = rx.to_bytes(32, "big")

    e = (
        int.from_bytes(
            tagged_hash("BIP0340/challenge", rx_bytes + px_bytes + msg32), "big"
        )
        % _N
    )
    s = (k + e * d) % _N
    return rx_bytes + s.to_bytes(32, "big")


def schnorr_verify(msg32: bytes, pubkey32: bytes, sig64: bytes) -> bool:
    """Verify a 64-byte BIP-340 Schnorr signature."""
    if len(msg32) != 32 or len(pubkey32) != 32 or len(sig64) != 64:
        return False
    P = _lift_x(int.from_bytes(pubkey32, "big"))
    if P is None:
        return False
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if r >= _P or s >= _N:
        return False
    e = (
        int.from_bytes(
            tagged_hash("BIP0340/challenge", sig64[:32] + pubkey32 + msg32), "big"
        )
        % _N
    )
    # R = s*G - e*P
    sG = _jac_mul(s, _G)
    neg_P: _JacPoint = (P[0], (_P - P[1]) % _P, 1)
    e_neg_P = _jac_mul(e, neg_P)
    R = _to_affine(_jac_add(sG, e_neg_P))
    if R is None:
        return False
    rx, ry = R
    if ry % 2 != 0 or rx != r:
        return False
    return True


def ecdh_shared_x(privkey32: bytes, peer_pubkey32: bytes) -> bytes:
    """Compute the unhashed 32-byte ECDH shared x-coordinate for NIP-04 / NIP-44."""
    if len(privkey32) != 32 or len(peer_pubkey32) != 32:
        raise ValueError("Keys must be 32 bytes")
    d = int.from_bytes(privkey32, "big")
    if not (1 <= d < _N):
        raise ValueError("Invalid private key scalar")
    peer_pt = _lift_x(int.from_bytes(peer_pubkey32, "big"))
    if peer_pt is None:
        raise ValueError("Invalid peer public key")
    shared = _to_affine(_jac_mul(d, (peer_pt[0], peer_pt[1], 1)))
    if shared is None:
        raise ValueError("Invalid shared secret point")
    return shared[0].to_bytes(32, "big")


# ── Pure-Python AES-256-CBC (for NIP-04) ──────────────────────────

_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_AES_INV_SBOX = [0] * 256
for _idx, _val in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_val] = _idx

_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _aes256_expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    w: list[list[int]] = [list(key[i : i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = list(w[i - 1])
        if i % 8 == 0:
            temp = [
                _AES_SBOX[temp[1]] ^ _RCON[i // 8],
                _AES_SBOX[temp[2]],
                _AES_SBOX[temp[3]],
                _AES_SBOX[temp[0]],
            ]
        elif i % 8 == 4:
            temp = [_AES_SBOX[b] for b in temp]
        w.append([w[i - 8][j] ^ temp[j] for j in range(4)])
    round_keys: list[list[int]] = []
    for r in range(15):
        rk: list[int] = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        round_keys.append(rk)
    return round_keys


def _aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    s = [block[i] ^ round_keys[0][i] for i in range(16)]
    for r in range(1, 14):
        # SubBytes + ShiftRows combined
        s = [
            _AES_SBOX[s[0]],  _AES_SBOX[s[5]],  _AES_SBOX[s[10]], _AES_SBOX[s[15]],
            _AES_SBOX[s[4]],  _AES_SBOX[s[9]],  _AES_SBOX[s[14]], _AES_SBOX[s[3]],
            _AES_SBOX[s[8]],  _AES_SBOX[s[13]], _AES_SBOX[s[2]],  _AES_SBOX[s[7]],
            _AES_SBOX[s[12]], _AES_SBOX[s[1]],  _AES_SBOX[s[6]],  _AES_SBOX[s[11]],
        ]
        # MixColumns + AddRoundKey
        rk = round_keys[r]
        for c in range(0, 16, 4):
            a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
            t = a0 ^ a1 ^ a2 ^ a3
            s[c]     = a0 ^ t ^ _xtime(a0 ^ a1) ^ rk[c]
            s[c + 1] = a1 ^ t ^ _xtime(a1 ^ a2) ^ rk[c + 1]
            s[c + 2] = a2 ^ t ^ _xtime(a2 ^ a3) ^ rk[c + 2]
            s[c + 3] = a3 ^ t ^ _xtime(a3 ^ a0) ^ rk[c + 3]
    # Final round (no MixColumns)
    rk = round_keys[14]
    s = [
        _AES_SBOX[s[0]] ^ rk[0],   _AES_SBOX[s[5]] ^ rk[1],   _AES_SBOX[s[10]] ^ rk[2],  _AES_SBOX[s[15]] ^ rk[3],
        _AES_SBOX[s[4]] ^ rk[4],   _AES_SBOX[s[9]] ^ rk[5],   _AES_SBOX[s[14]] ^ rk[6],  _AES_SBOX[s[3]] ^ rk[7],
        _AES_SBOX[s[8]] ^ rk[8],   _AES_SBOX[s[13]] ^ rk[9],  _AES_SBOX[s[2]] ^ rk[10],  _AES_SBOX[s[7]] ^ rk[11],
        _AES_SBOX[s[12]] ^ rk[12], _AES_SBOX[s[1]] ^ rk[13],  _AES_SBOX[s[6]] ^ rk[14],  _AES_SBOX[s[11]] ^ rk[15],
    ]
    return bytes(s)


def _aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    rk = round_keys[14]
    s = [block[i] ^ rk[i] for i in range(16)]
    for r in range(13, 0, -1):
        # InvShiftRows + InvSubBytes
        s = [
            _AES_INV_SBOX[s[0]],  _AES_INV_SBOX[s[13]], _AES_INV_SBOX[s[10]], _AES_INV_SBOX[s[7]],
            _AES_INV_SBOX[s[4]],  _AES_INV_SBOX[s[1]],  _AES_INV_SBOX[s[14]], _AES_INV_SBOX[s[11]],
            _AES_INV_SBOX[s[8]],  _AES_INV_SBOX[s[5]],  _AES_INV_SBOX[s[2]],  _AES_INV_SBOX[s[15]],
            _AES_INV_SBOX[s[12]], _AES_INV_SBOX[s[9]],  _AES_INV_SBOX[s[6]],  _AES_INV_SBOX[s[3]],
        ]
        # AddRoundKey + InvMixColumns
        rk = round_keys[r]
        for i in range(16):
            s[i] ^= rk[i]
        for c in range(0, 16, 4):
            a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
            s[c]     = _gmul(a0, 0x0E) ^ _gmul(a1, 0x0B) ^ _gmul(a2, 0x0D) ^ _gmul(a3, 0x09)
            s[c + 1] = _gmul(a0, 0x09) ^ _gmul(a1, 0x0E) ^ _gmul(a2, 0x0B) ^ _gmul(a3, 0x0D)
            s[c + 2] = _gmul(a0, 0x0D) ^ _gmul(a1, 0x09) ^ _gmul(a2, 0x0E) ^ _gmul(a3, 0x0B)
            s[c + 3] = _gmul(a0, 0x0B) ^ _gmul(a1, 0x0D) ^ _gmul(a2, 0x09) ^ _gmul(a3, 0x0E)
    rk = round_keys[0]
    s = [
        _AES_INV_SBOX[s[0]] ^ rk[0],   _AES_INV_SBOX[s[13]] ^ rk[1],  _AES_INV_SBOX[s[10]] ^ rk[2],  _AES_INV_SBOX[s[7]] ^ rk[3],
        _AES_INV_SBOX[s[4]] ^ rk[4],   _AES_INV_SBOX[s[1]] ^ rk[5],   _AES_INV_SBOX[s[14]] ^ rk[6],  _AES_INV_SBOX[s[11]] ^ rk[7],
        _AES_INV_SBOX[s[8]] ^ rk[8],   _AES_INV_SBOX[s[5]] ^ rk[9],   _AES_INV_SBOX[s[2]] ^ rk[10],  _AES_INV_SBOX[s[15]] ^ rk[11],
        _AES_INV_SBOX[s[12]] ^ rk[12], _AES_INV_SBOX[s[9]] ^ rk[13],  _AES_INV_SBOX[s[6]] ^ rk[14],  _AES_INV_SBOX[s[3]] ^ rk[15],
    ]
    return bytes(s)


def aes256_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    round_keys = _aes256_expand_key(key)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        blk = bytes(a ^ b for a, b in zip(padded[i : i + 16], prev))
        enc = _aes_encrypt_block(blk, round_keys)
        out.extend(enc)
        prev = enc
    return bytes(out)


def aes256_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a positive multiple of 16")
    round_keys = _aes256_expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        ct_blk = ciphertext[i : i + 16]
        dec = _aes_decrypt_block(ct_blk, round_keys)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = ct_blk
    pad_len = out[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS#7 padding")
    if any(b != pad_len for b in out[-pad_len:]):
        raise ValueError("Corrupted PKCS#7 padding")
    return bytes(out[:-pad_len])


# ── NIP-04 Encryption / Decryption ────────────────────────────────


def nip04_encrypt(
    plaintext: str,
    privkey32: bytes,
    peer_pubkey32: bytes,
    iv: bytes | None = None,
) -> str:
    shared_key = ecdh_shared_x(privkey32, peer_pubkey32)
    if iv is None:
        iv = secrets.token_bytes(16)
    ct = aes256_cbc_encrypt(shared_key, iv, plaintext.encode("utf-8"))
    return f"{base64.b64encode(ct).decode('ascii')}?iv={base64.b64encode(iv).decode('ascii')}"


def nip04_decrypt(
    payload: str, privkey32: bytes, peer_pubkey32: bytes
) -> str:
    if "?iv=" not in payload:
        raise ValueError("NIP-04 payload missing ?iv=")
    ct_b64, iv_b64 = payload.split("?iv=", 1)
    ct = base64.b64decode(ct_b64)
    iv = base64.b64decode(iv_b64)
    shared_key = ecdh_shared_x(privkey32, peer_pubkey32)
    pt = aes256_cbc_decrypt(shared_key, iv, ct)
    return pt.decode("utf-8")


# ── Pure-Python ChaCha20 & NIP-44 v2 ──────────────────────────────


def _rotl32(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = list(
        struct.unpack("<4I8I1I3I", b"expand 32-byte k" + key + struct.pack("<I", counter) + nonce)
    )
    w = list(state)
    for _ in range(10):
        # Column rounds
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)):
            w[a] = (w[a] + w[b]) & 0xFFFFFFFF; w[d] = _rotl32(w[d] ^ w[a], 16)
            w[c] = (w[c] + w[d]) & 0xFFFFFFFF; w[b] = _rotl32(w[b] ^ w[c], 12)
            w[a] = (w[a] + w[b]) & 0xFFFFFFFF; w[d] = _rotl32(w[d] ^ w[a], 8)
            w[c] = (w[c] + w[d]) & 0xFFFFFFFF; w[b] = _rotl32(w[b] ^ w[c], 7)
        # Diagonal rounds
        for a, b, c, d in ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            w[a] = (w[a] + w[b]) & 0xFFFFFFFF; w[d] = _rotl32(w[d] ^ w[a], 16)
            w[c] = (w[c] + w[d]) & 0xFFFFFFFF; w[b] = _rotl32(w[b] ^ w[c], 12)
            w[a] = (w[a] + w[b]) & 0xFFFFFFFF; w[d] = _rotl32(w[d] ^ w[a], 8)
            w[c] = (w[c] + w[d]) & 0xFFFFFFFF; w[b] = _rotl32(w[b] ^ w[c], 7)
    return struct.pack("<16I", *((w[i] + state[i]) & 0xFFFFFFFF for i in range(16)))


def chacha20_crypt(key: bytes, nonce: bytes, data: bytes, initial_counter: int = 0) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20 requires 32-byte key and 12-byte nonce")
    out = bytearray(len(data))
    counter = initial_counter
    for offset in range(0, len(data), 64):
        stream = _chacha20_block(key, counter, nonce)
        chunk = data[offset : offset + 64]
        for i, b in enumerate(chunk):
            out[offset + i] = b ^ stream[i]
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(out)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out.extend(t)
        counter += 1
    return bytes(out[:length])


def nip44_conversation_key(privkey32: bytes, peer_pubkey32: bytes) -> bytes:
    shared_x = ecdh_shared_x(privkey32, peer_pubkey32)
    return _hkdf_extract(b"nip44-v2", shared_x)


def nip44_get_message_keys(
    conversation_key: bytes, nonce: bytes
) -> tuple[bytes, bytes, bytes]:
    if len(conversation_key) != 32 or len(nonce) != 32:
        raise ValueError("conversation_key and nonce must be 32 bytes")
    keys = _hkdf_expand(conversation_key, nonce, 76)
    return keys[0:32], keys[32:44], keys[44:76]


def nip44_calc_padded_len(unpadded_len: int) -> int:
    if unpadded_len < 1 or unpadded_len > 65535:
        raise ValueError(f"Invalid NIP-44 plaintext length: {unpadded_len}")
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (unpadded_len - 1).bit_length()
    chunk = max(32, next_power >> 3)
    return chunk * ((unpadded_len + chunk - 1) // chunk)


def nip44_pad(plaintext: str) -> bytes:
    raw = plaintext.encode("utf-8")
    n = len(raw)
    padded_len = nip44_calc_padded_len(n)
    return struct.pack(">H", n) + raw + (b"\x00" * (padded_len - n))


def nip44_unpad(padded: bytes) -> str:
    if len(padded) < 34:
        raise ValueError("Invalid padded data length")
    n = struct.unpack(">H", padded[:2])[0]
    if n < 1 or n > len(padded) - 2:
        raise ValueError("Invalid NIP-44 length prefix")
    expected_len = 2 + nip44_calc_padded_len(n)
    if len(padded) != expected_len:
        raise ValueError("Invalid NIP-44 padded length")
    if any(b != 0 for b in padded[2 + n :]):
        raise ValueError("Non-zero padding bytes in NIP-44 payload")
    return padded[2 : 2 + n].decode("utf-8")


def nip44_encrypt_with_conv_key(
    plaintext: str, conversation_key: bytes, nonce: bytes | None = None
) -> str:
    if nonce is None:
        nonce = secrets.token_bytes(32)
    chacha_key, chacha_nonce, hmac_key = nip44_get_message_keys(conversation_key, nonce)
    padded = nip44_pad(plaintext)
    ciphertext = chacha20_crypt(chacha_key, chacha_nonce, padded)
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ciphertext + mac).decode("ascii")


def nip44_decrypt_with_conv_key(payload: str, conversation_key: bytes) -> str:
    if not payload or payload.startswith("#"):
        raise ValueError("Unsupported NIP-44 encryption version")
    if len(payload) < 132 or len(payload) > 87472:
        raise ValueError("Invalid NIP-44 base64 payload size")
    raw = base64.b64decode(payload)
    if len(raw) < 99 or len(raw) > 65603:
        raise ValueError("Invalid NIP-44 decoded size")
    if raw[0] != 2:
        raise ValueError(f"Unknown NIP-44 version: {raw[0]}")
    nonce = raw[1:33]
    ciphertext = raw[33:-32]
    mac = raw[-32:]
    chacha_key, chacha_nonce, hmac_key = nip44_get_message_keys(conversation_key, nonce)
    expected_mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, mac):
        raise ValueError("Invalid NIP-44 MAC")
    padded = chacha20_crypt(chacha_key, chacha_nonce, ciphertext)
    return nip44_unpad(padded)


def nip44_encrypt(
    plaintext: str,
    privkey32: bytes,
    peer_pubkey32: bytes,
    nonce: bytes | None = None,
) -> str:
    conv = nip44_conversation_key(privkey32, peer_pubkey32)
    return nip44_encrypt_with_conv_key(plaintext, conv, nonce=nonce)


def nip44_decrypt(
    payload: str, privkey32: bytes, peer_pubkey32: bytes
) -> str:
    conv = nip44_conversation_key(privkey32, peer_pubkey32)
    return nip44_decrypt_with_conv_key(payload, conv)


# ── NIP-01 Event Helpers ──────────────────────────────────────────


def compute_event_id(
    pubkey_hex: str,
    created_at: int,
    kind: int,
    tags: list[list[str]],
    content: str,
) -> str:
    serialized = json.dumps(
        [0, pubkey_hex.lower(), int(created_at), int(kind), tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def make_event(
    privkey_hex: str,
    kind: int,
    content: str,
    tags: list[list[str]],
    created_at: int | None = None,
) -> dict:
    priv32 = bytes.fromhex(privkey_hex)
    pub_hex = pubkey_from_privkey(priv32).hex()
    ts = int(time.time()) if created_at is None else int(created_at)
    ev_id = compute_event_id(pub_hex, ts, kind, tags, content)
    sig = schnorr_sign(bytes.fromhex(ev_id), priv32).hex()
    return {
        "id": ev_id,
        "pubkey": pub_hex,
        "created_at": ts,
        "kind": int(kind),
        "tags": tags,
        "content": content,
        "sig": sig,
    }


def verify_event(event: dict) -> bool:
    try:
        ev_id = str(event.get("id", "")).lower()
        pubkey = str(event.get("pubkey", "")).lower()
        created_at = int(event["created_at"])
        kind = int(event["kind"])
        tags = event.get("tags") or []
        content = str(event.get("content", ""))
        sig = str(event.get("sig", "")).lower()
        if len(ev_id) != 64 or len(pubkey) != 64 or len(sig) != 128:
            return False
        expected_id = compute_event_id(pubkey, created_at, kind, tags, content)
        if expected_id != ev_id:
            return False
        return schnorr_verify(
            bytes.fromhex(ev_id),
            bytes.fromhex(pubkey),
            bytes.fromhex(sig),
        )
    except Exception:
        return False


# ── Minimal RFC 6455 WebSocket Client (with SOCKS5 for .onion) ────

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _connect_socks5(
    proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: float
) -> socket.socket:
    """Connect to target_host:target_port through a SOCKS5 proxy (e.g. Tor)."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    # Greeting: version 5, 1 auth method (0x00 = no auth)
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
        sock.close()
        raise OSError("SOCKS5 proxy handshake failed")
    host_bytes = target_host.encode("idna")
    req = (
        b"\x05\x01\x00\x03"
        + bytes([len(host_bytes)])
        + host_bytes
        + struct.pack(">H", target_port)
    )
    sock.sendall(req)
    hdr = sock.recv(4)
    if len(hdr) != 4 or hdr[0] != 5 or hdr[1] != 0:
        sock.close()
        raise OSError(f"SOCKS5 connect to {target_host}:{target_port} failed")
    atyp = hdr[3]
    if atyp == 1:
        sock.recv(4 + 2)
    elif atyp == 3:
        ln = sock.recv(1)[0]
        sock.recv(ln + 2)
    elif atyp == 4:
        sock.recv(16 + 2)
    return sock


def _tls_context() -> ssl.SSLContext:
    """TLS context for `wss://` relay and LNURL connections.

    `ssl.create_default_context()` already yields `PROTOCOL_TLS_CLIENT` with
    hostname checking and certificate verification, but its protocol floor is
    implicit. Pin it to TLS 1.2 so the minimum is enforced by this code rather
    than inferred from the interpreter version (`ssl.TLSVersion` needs 3.7+,
    which is older than any Python this daemon supports). Static analysis
    (`py/insecure-protocol`, CWE-327) cannot see the implicit default and
    flags a bare `create_default_context()`, so this also keeps the scanner
    honest about what is actually allowed.
    """
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class WebSocketConnection:
    """Thread-safe RFC 6455 client connection."""

    def __init__(
        self,
        url: str,
        timeout: float = 15.0,
        socks5_proxy: str | None = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.socks5_proxy = socks5_proxy
        self._sock: socket.socket | ssl.SSLSocket | None = None
        self._send_lock = threading.Lock()
        self._closed = False

    def connect(self) -> None:
        parsed = urllib.parse.urlparse(self.url)
        scheme = parsed.scheme.lower()
        if scheme not in ("ws", "wss"):
            raise ValueError(f"Unsupported WebSocket scheme: {scheme}")
        host = parsed.hostname
        if not host:
            raise ValueError(f"Invalid WebSocket URL: {self.url}")
        port = parsed.port or (443 if scheme == "wss" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        use_socks = self.socks5_proxy and (
            host.endswith(".onion") or os.environ.get("NWC_FORCE_TOR_RELAY") == "1"
        )
        if use_socks and self.socks5_proxy:
            phost, pport_str = self.socks5_proxy.rsplit(":", 1)
            raw_sock = _connect_socks5(phost, int(pport_str), host, port, self.timeout)
        else:
            raw_sock = socket.create_connection((host, port), timeout=self.timeout)

        if scheme == "wss":
            self._sock = _tls_context().wrap_socket(raw_sock, server_hostname=host)
        else:
            self._sock = raw_sock

        ws_key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        host_hdr = f"{host}:{port}" if parsed.port else host
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"User-Agent: sovran-nwc/2.0\r\n\r\n"
        )
        self._sock.sendall(handshake.encode("ascii"))

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise OSError("WebSocket closed during HTTP upgrade")
            buf += chunk
            if len(buf) > 65536:
                raise OSError("WebSocket HTTP upgrade header too large")

        header_part, _ = buf.split(b"\r\n\r\n", 1)
        lines = header_part.decode("iso-8859-1").split("\r\n")
        if not lines or " 101 " not in lines[0]:
            raise OSError(f"WebSocket upgrade rejected: {lines[0] if lines else 'empty'}")

        expected_accept = base64.b64encode(
            hashlib.sha1((ws_key + _WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if headers.get("sec-websocket-accept") != expected_accept:
            raise OSError("Invalid Sec-WebSocket-Accept header")

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("WebSocket connection closed")
            buf.extend(chunk)
        return bytes(buf)

    def send_frame(self, opcode: int, payload: bytes) -> None:
        if self._closed or self._sock is None:
            raise EOFError("WebSocket is closed")
        mask_key = secrets.token_bytes(4)
        header = bytearray()
        header.append(0x80 | (opcode & 0x0F))
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack(">H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack(">Q", length))
        header.extend(mask_key)
        masked = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
        with self._send_lock:
            self._sock.sendall(bytes(header) + masked)

    def send_text(self, text: str) -> None:
        self.send_frame(0x1, text.encode("utf-8"))

    def send_json(self, obj: object) -> None:
        self.send_text(json.dumps(obj, separators=(",", ":")))

    def recv_message(self) -> str | None:
        fragments: list[bytes] = []
        while not self._closed:
            b1, b2 = self._recv_exact(2)
            fin = bool(b1 & 0x80)
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._recv_exact(8))[0]
            if length > 4 * 1024 * 1024:
                raise OSError("WebSocket frame exceeds 4 MiB limit")
            mask_key = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(length) if length else b""
            if masked:
                payload = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))

            if opcode == 0x8:  # Close
                self.close()
                return None
            if opcode == 0x9:  # Ping -> send Pong
                self.send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # Pong
                continue
            if opcode in (0x1, 0x2, 0x0):
                fragments.append(payload)
                if fin:
                    raw = b"".join(fragments)
                    fragments.clear()
                    return raw.decode("utf-8", errors="replace")
        return None

    def close(self) -> None:
        self._closed = True
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
