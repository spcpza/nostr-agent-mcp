"""
Cryptographic primitives for Nostr agent identity and messaging.

Implements:
  - NIP-01: secp256k1 keypair generation and Schnorr signing
  - NIP-44 v2: encrypted direct messages
      ECDH shared secret → HKDF-SHA256 → ChaCha20-Poly1305 AEAD

Pure Python — no C extensions required. Depends only on the
standard library + `cryptography` package (widely available).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from typing import Optional


# ---------------------------------------------------------------------------
# secp256k1 field / group parameters
# ---------------------------------------------------------------------------

_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _modinv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0]:
        if P[1] != Q[1]: return None
        lam = (3 * P[0] * P[0] * _modinv(2 * P[1], _P)) % _P
    else:
        lam = ((Q[1] - P[1]) * _modinv(Q[0] - P[0], _P)) % _P
    x = (lam * lam - P[0] - Q[0]) % _P
    y = (lam * (P[0] - x) - P[1]) % _P
    return (x, y)


def _point_mul(k: int, P):
    R = None
    while k:
        if k & 1: R = _point_add(R, P)
        P = _point_add(P, P)
        k >>= 1
    return R


_G = (_Gx, _Gy)


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def generate_privkey() -> str:
    """Generate a random 32-byte private key (hex)."""
    return secrets.token_hex(32)


def pubkey_from_privkey(privkey_hex: str) -> str:
    """Derive the 32-byte x-only public key (hex) from a private key."""
    k = int(privkey_hex, 16)
    point = _point_mul(k, _G)
    return format(point[0], "064x")


def load_privkey(privkey_hex: Optional[str] = None) -> str:
    """Load private key from arg, env (NOSTR_NSEC / NOSTR_HEX_KEY), or generate."""
    import os
    if privkey_hex:
        return _normalise_privkey(privkey_hex)
    nsec = os.environ.get("NOSTR_NSEC", "")
    if nsec.startswith("nsec1"):
        return _decode_nsec(nsec)
    hexkey = os.environ.get("NOSTR_HEX_KEY", "")
    if hexkey:
        return hexkey
    # No key found — generate a fresh one and print warning
    key = generate_privkey()
    print(f"[agent-mcp] No NOSTR_NSEC/NOSTR_HEX_KEY set. Generated ephemeral key: {key}")
    print("[agent-mcp] Set NOSTR_NSEC or NOSTR_HEX_KEY env var for a persistent identity.")
    return key


def _normalise_privkey(key: str) -> str:
    if key.startswith("nsec1"):
        return _decode_nsec(key)
    return key


def _decode_nsec(nsec: str) -> str:
    """Decode bech32 nsec → hex privkey."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    _, data_part = nsec.lower().split("1", 1)
    decoded = []
    for c in data_part[:-6]:
        decoded.append(CHARSET.index(c))
    # convert 5-bit groups to 8-bit bytes
    acc, bits, result = 0, 0, []
    for val in decoded:
        acc = (acc << 5) | val
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((acc >> bits) & 0xFF)
    return bytes(result[1:33]).hex()  # skip witness version byte


# ---------------------------------------------------------------------------
# NIP-01 Schnorr signing
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _bytes_from_int(i: int) -> bytes:
    return i.to_bytes(32, "big")


def _has_even_y(point) -> bool:
    return point[1] % 2 == 0


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = _sha256(tag.encode())
    return _sha256(tag_hash + tag_hash + data)


def _schnorr_sign(msg: bytes, privkey_hex: str) -> str:
    """BIP-340 Schnorr signature. Returns 64-byte signature hex."""
    assert len(msg) == 32
    sk = int(privkey_hex, 16)
    P = _point_mul(sk, _G)
    if not _has_even_y(P):
        sk = _N - sk
    aux_rand = os.urandom(32)
    t = sk ^ _int_from_bytes(_tagged_hash("BIP0340/aux", aux_rand))
    rand = _tagged_hash("BIP0340/nonce", _bytes_from_int(t) + _bytes_from_int(P[0]) + msg)
    k = _int_from_bytes(rand) % _N
    assert k != 0
    R = _point_mul(k, _G)
    if not _has_even_y(R):
        k = _N - k
    e = _int_from_bytes(
        _tagged_hash("BIP0340/challenge", _bytes_from_int(R[0]) + _bytes_from_int(P[0]) + msg)
    ) % _N
    sig = _bytes_from_int(R[0]) + _bytes_from_int((k + e * sk) % _N)
    return sig.hex()


def sign_event(kind: int, content: str, tags: list, privkey_hex: str) -> dict:
    """Construct, sign, and return a NIP-01 Nostr event dict."""
    pubkey = pubkey_from_privkey(privkey_hex)
    created_at = int(time.time())
    serial = json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    event_id = _sha256(serial.encode()).hex()
    sig = _schnorr_sign(bytes.fromhex(event_id), privkey_hex)
    return {
        "id": event_id,
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig,
    }


# ---------------------------------------------------------------------------
# NIP-44 v2 — encrypted direct messages
# ---------------------------------------------------------------------------
# Spec: https://github.com/nostr-protocol/nips/blob/master/44.md
#
# Encryption:
#   1. ECDH: shared_x = (privkey_A * pubkey_B).x
#   2. HKDF-SHA256(shared_x, salt=random_32, info=b"nip44-v2") → 32-byte key
#   3. ChaCha20-Poly1305 encrypt (nonce = 0-filled 12 bytes for ChaCha20 in
#      the standard NIP-44 v2 spec, the nonce is derived differently — see below)
#
# NIP-44 v2 actual key derivation:
#   conversation_key = HKDF-extract(salt=shared_x, ikm=b"") ... actually:
#   conversation_key = HMAC-SHA256(key=salt, msg=shared_x)  [HKDF-extract step]
#   then message_keys = HKDF-expand(conversation_key, info=b"nip44-v2", length=76)
#   chacha_key  = message_keys[0:32]
#   chacha_nonce = message_keys[32:44]
#   hmac_key    = message_keys[44:76]

def _ecdh_shared_point(privkey_hex: str, pubkey_hex: str) -> bytes:
    """Compute ECDH shared x-coordinate."""
    sk = int(privkey_hex, 16)
    # Reconstruct full point from x-only pubkey (even y)
    x = int(pubkey_hex, 16)
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if y % 2 != 0:
        y = _P - y
    peer_point = (x, y)
    shared = _point_mul(sk, peer_point)
    return shared[0].to_bytes(32, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, T, i = b"", b"", 1
    while len(out) < length:
        T = hmac.new(prk, T + info + bytes([i]), hashlib.sha256).digest()
        out += T
        i += 1
    return out[:length]


def _derive_message_keys(conversation_key: bytes, nonce_32: bytes) -> tuple[bytes, bytes, bytes]:
    """Returns (chacha_key, chacha_nonce_12, hmac_key_32)."""
    keys = _hkdf_expand(conversation_key, b"nip44-v2" + nonce_32, 76)
    return keys[:32], keys[32:44], keys[44:76]


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Single ChaCha20 64-byte keystream block."""
    def _rot(v, n): return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF
    def _QR(s, a, b, c, d):
        s[a] = (s[a]+s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rot(s[d], 16)
        s[c] = (s[c]+s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rot(s[b], 12)
        s[a] = (s[a]+s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rot(s[d], 8)
        s[c] = (s[c]+s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rot(s[b], 7)

    const = b"expand 32-byte k"
    k = struct.unpack_from("<8I", key)
    n = struct.unpack_from("<3I", nonce)
    state = list(struct.unpack("<4I", const)) + list(k) + [counter] + list(n)
    working = state[:]
    for _ in range(10):
        _QR(working, 0,4,8,12); _QR(working, 1,5,9,13)
        _QR(working, 2,6,10,14); _QR(working, 3,7,11,15)
        _QR(working, 0,5,10,15); _QR(working, 1,6,11,12)
        _QR(working, 2,7,8,13); _QR(working, 3,4,9,14)
    return struct.pack("<16I", *((working[i]+state[i]) & 0xFFFFFFFF for i in range(16)))


def _chacha20_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Pure Python ChaCha20 stream cipher."""
    out = bytearray()
    for i in range(0, len(plaintext), 64):
        block = _chacha20_block(key, i // 64 + 1, nonce)
        chunk = plaintext[i:i+64]
        out += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)


def _pad_plaintext(plaintext: bytes) -> bytes:
    """NIP-44 v2 zero-padding to next power of 2 (min 32 bytes)."""
    L = len(plaintext)
    if L == 0: raise ValueError("Empty plaintext")
    chunk = max(32, 1 << (L - 1).bit_length() if L > 1 else 32)
    padded = struct.pack(">H", L) + plaintext + b"\x00" * (chunk - L)
    return padded


def _unpad_plaintext(padded: bytes) -> bytes:
    if len(padded) < 2: raise ValueError("Too short")
    L = struct.unpack_from(">H", padded)[0]
    return padded[2:2+L]


def nip44_encrypt(plaintext: str, sender_privkey_hex: str, recipient_pubkey_hex: str) -> str:
    """Encrypt a message per NIP-44 v2. Returns base64url payload."""
    shared_x = _ecdh_shared_point(sender_privkey_hex, recipient_pubkey_hex)
    salt = os.urandom(32)
    conv_key = _hkdf_extract(salt, shared_x)
    chacha_key, chacha_nonce, mac_key = _derive_message_keys(conv_key, salt)

    padded = _pad_plaintext(plaintext.encode())
    ciphertext = _chacha20_encrypt(chacha_key, chacha_nonce, padded)
    mac = hmac.new(mac_key, salt + ciphertext, hashlib.sha256).digest()

    payload = bytes([2]) + salt + ciphertext + mac
    return base64.b64encode(payload).decode()


def nip44_decrypt(payload_b64: str, recipient_privkey_hex: str, sender_pubkey_hex: str) -> str:
    """Decrypt a NIP-44 v2 payload. Returns plaintext string."""
    payload = base64.b64decode(payload_b64)
    if payload[0] != 2:
        raise ValueError(f"Unsupported NIP-44 version: {payload[0]}")
    salt = payload[1:33]
    ciphertext = payload[33:-32]
    mac = payload[-32:]

    shared_x = _ecdh_shared_point(recipient_privkey_hex, sender_pubkey_hex)
    conv_key = _hkdf_extract(salt, shared_x)
    chacha_key, chacha_nonce, mac_key = _derive_message_keys(conv_key, salt)

    expected_mac = hmac.new(mac_key, salt + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("NIP-44 MAC verification failed — message tampered or wrong key")

    plaintext = _chacha20_encrypt(chacha_key, chacha_nonce, ciphertext)
    return _unpad_plaintext(plaintext).decode()
