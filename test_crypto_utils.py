"""
test_crypto_utils.py - Automated tests for crypto_utils.py.

Run with:  pytest -v

Each function starting with "test_" is one test. A test passes if it finishes
without errors, and fails if an assert is False or an exception is raised.
"""

import pytest
from cryptography.exceptions import InvalidTag

from crypto_utils import (
    generate_keypair, public_key_to_bytes, public_key_from_bytes,
    rsa_encrypt, rsa_decrypt,
    generate_aes_key, aes_encrypt, aes_decrypt,
    fingerprint,
)


# ---------------------------------------------------------------- RSA ----

def test_rsa_round_trip():
    """Data locked with the public key is recovered by the private key."""
    private_key, public_key = generate_keypair()
    locked = rsa_encrypt(public_key, b"hello bob")
    assert rsa_decrypt(private_key, locked) == b"hello bob"


def test_rsa_wrong_private_key_fails():
    """A different user's private key must NOT be able to unlock the data."""
    _, alice_public = generate_keypair()
    eve_private, _ = generate_keypair()
    locked = rsa_encrypt(alice_public, b"secret")
    with pytest.raises(ValueError):
        rsa_decrypt(eve_private, locked)


def test_rsa_rejects_data_that_is_too_large():
    """RSA can only lock small data (~190 bytes); this is why we use AES too."""
    _, public_key = generate_keypair()
    with pytest.raises(ValueError):
        rsa_encrypt(public_key, b"x" * 300)


def test_public_key_survives_network_transfer():
    """A public key converted to bytes and rebuilt still works."""
    private_key, public_key = generate_keypair()
    rebuilt = public_key_from_bytes(public_key_to_bytes(public_key))
    locked = rsa_encrypt(rebuilt, b"test")
    assert rsa_decrypt(private_key, locked) == b"test"


# ---------------------------------------------------------------- AES ----

def test_aes_round_trip():
    """AES-encrypted data decrypts back to the original."""
    key = generate_aes_key()
    blob = aes_encrypt(key, b"hello world")
    assert aes_decrypt(key, blob) == b"hello world"


def test_aes_handles_large_messages():
    """Unlike RSA, AES handles large data without problems."""
    key = generate_aes_key()
    message = b"x" * 100_000
    assert aes_decrypt(key, aes_encrypt(key, message)) == message


def test_aes_same_message_gives_different_ciphertext():
    """The random nonce means encrypting the same text twice never matches."""
    key = generate_aes_key()
    assert aes_encrypt(key, b"same") != aes_encrypt(key, b"same")


def test_aes_detects_tampering():
    """Changing a single bit of the encrypted data must be detected."""
    key = generate_aes_key()
    tampered = bytearray(aes_encrypt(key, b"hello world"))
    tampered[20] ^= 1
    with pytest.raises(InvalidTag):
        aes_decrypt(key, bytes(tampered))


def test_aes_wrong_key_fails():
    """Decrypting with a different key must fail."""
    blob = aes_encrypt(generate_aes_key(), b"hello world")
    with pytest.raises(InvalidTag):
        aes_decrypt(generate_aes_key(), blob)


# ------------------------------------------------------- Fingerprints ----

def test_fingerprint_is_deterministic():
    """The same key always produces the same fingerprint."""
    _, public_key = generate_keypair()
    key_bytes = public_key_to_bytes(public_key)
    assert fingerprint(key_bytes) == fingerprint(key_bytes)


def test_fingerprint_differs_between_keys():
    """Different keys produce different fingerprints (what catches a swap)."""
    _, key_a = generate_keypair()
    _, key_b = generate_keypair()
    assert fingerprint(public_key_to_bytes(key_a)) != fingerprint(public_key_to_bytes(key_b))


def test_fingerprint_format():
    """8 groups of 4 hex characters, separated by spaces."""
    _, public_key = generate_keypair()
    groups = fingerprint(public_key_to_bytes(public_key)).split(" ")
    assert len(groups) == 8
    assert all(len(g) == 4 for g in groups)