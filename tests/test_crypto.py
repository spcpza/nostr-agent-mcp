"""Tests for NIP-01 signing and NIP-44 encrypted messaging."""

import pytest
from agent_mcp.crypto import (
    generate_privkey,
    nip44_decrypt,
    nip44_encrypt,
    pubkey_from_privkey,
    sign_event,
)


class TestKeypairs:
    def test_generate_privkey_length(self):
        key = generate_privkey()
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_pubkey_from_privkey_length(self):
        priv = generate_privkey()
        pub = pubkey_from_privkey(priv)
        assert len(pub) == 64

    def test_deterministic_pubkey(self):
        priv = "a" * 64
        assert pubkey_from_privkey(priv) == pubkey_from_privkey(priv)

    def test_different_privkeys_different_pubkeys(self):
        a = generate_privkey()
        b = generate_privkey()
        assert pubkey_from_privkey(a) != pubkey_from_privkey(b)


class TestSignEvent:
    def test_event_has_required_fields(self):
        priv = generate_privkey()
        event = sign_event(1, "hello nostr", [], priv)
        for field in ("id", "pubkey", "created_at", "kind", "tags", "content", "sig"):
            assert field in event

    def test_event_kind_and_content(self):
        priv = generate_privkey()
        event = sign_event(17, "test dm", [["p", "abc"]], priv)
        assert event["kind"] == 17
        assert event["content"] == "test dm"
        assert event["tags"] == [["p", "abc"]]

    def test_event_id_is_hex32(self):
        priv = generate_privkey()
        event = sign_event(1, "content", [], priv)
        assert len(event["id"]) == 64
        assert len(event["sig"]) == 128

    def test_pubkey_matches_privkey(self):
        priv = generate_privkey()
        event = sign_event(1, "x", [], priv)
        assert event["pubkey"] == pubkey_from_privkey(priv)


class TestNIP44Encryption:
    def _keypair(self):
        priv = generate_privkey()
        pub = pubkey_from_privkey(priv)
        return priv, pub

    def test_basic_roundtrip(self):
        alice_priv, alice_pub = self._keypair()
        bob_priv, bob_pub = self._keypair()

        ciphertext = nip44_encrypt("Hello, Bob!", alice_priv, bob_pub)
        plaintext = nip44_decrypt(ciphertext, bob_priv, alice_pub)
        assert plaintext == "Hello, Bob!"

    def test_unicode_message(self):
        alice_priv, alice_pub = self._keypair()
        bob_priv, bob_pub = self._keypair()

        msg = "Salut! Ça va? 🤖⚡₿"
        ct = nip44_encrypt(msg, alice_priv, bob_pub)
        pt = nip44_decrypt(ct, bob_priv, alice_pub)
        assert pt == msg

    def test_long_message(self):
        alice_priv, alice_pub = self._keypair()
        bob_priv, bob_pub = self._keypair()

        msg = "The quick brown fox jumped over the lazy dog. " * 50
        ct = nip44_encrypt(msg, alice_priv, bob_pub)
        pt = nip44_decrypt(ct, bob_priv, alice_pub)
        assert pt == msg

    def test_each_encryption_is_unique(self):
        """Same plaintext encrypted twice should produce different ciphertexts (random salt)."""
        alice_priv, _ = self._keypair()
        _, bob_pub = self._keypair()
        ct1 = nip44_encrypt("same message", alice_priv, bob_pub)
        ct2 = nip44_encrypt("same message", alice_priv, bob_pub)
        assert ct1 != ct2

    def test_wrong_recipient_key_fails(self):
        alice_priv, alice_pub = self._keypair()
        bob_priv, bob_pub = self._keypair()
        carol_priv, _ = self._keypair()

        ct = nip44_encrypt("secret", alice_priv, bob_pub)
        with pytest.raises(ValueError, match="MAC"):
            nip44_decrypt(ct, carol_priv, alice_pub)

    def test_tampered_ciphertext_fails(self):
        import base64
        alice_priv, alice_pub = self._keypair()
        bob_priv, bob_pub = self._keypair()

        ct = nip44_encrypt("secret message", alice_priv, bob_pub)
        raw = bytearray(base64.b64decode(ct))
        raw[50] ^= 0xFF  # flip a byte in the ciphertext
        tampered = base64.b64encode(bytes(raw)).decode()

        with pytest.raises(ValueError):
            nip44_decrypt(tampered, bob_priv, alice_pub)

    def test_empty_string_message(self):
        alice_priv, alice_pub = self._keypair()
        bob_priv, bob_pub = self._keypair()
        # NIP-44 requires at least 1 byte plaintext
        with pytest.raises((ValueError, Exception)):
            nip44_encrypt("", alice_priv, bob_pub)

    def test_version_byte_is_2(self):
        import base64
        alice_priv, _ = self._keypair()
        _, bob_pub = self._keypair()
        ct = nip44_encrypt("test", alice_priv, bob_pub)
        raw = base64.b64decode(ct)
        assert raw[0] == 2  # NIP-44 v2


class TestIdentityEncoding:
    def test_npub_encoding(self):
        from agent_mcp.identity import _encode_npub
        priv = generate_privkey()
        pub = pubkey_from_privkey(priv)
        npub = _encode_npub(pub)
        assert npub.startswith("npub1")
        assert len(npub) > 10
