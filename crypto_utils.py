"""
crypto_utils.py - Encryption helpers for the chat app.

Uses hybrid encryption:
  - AES-256-GCM encrypts the actual message (fast, any size, detects tampering).
  - RSA-2048 (with OAEP padding) encrypts the small AES key so it can be
    shared safely using the recipient's public key.
"""

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------- RSA ----

def generate_keypair():
    """Create an RSA key pair. The public key is derived from the private key."""
    # 2048 bits is the common minimum; 65537 is the standard public exponent.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def public_key_to_bytes(public_key):
    """Convert a public key to PEM bytes so it can be sent over the network."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_bytes(data):
    """Rebuild a usable public key object from PEM bytes received from a peer."""
    return serialization.load_pem_public_key(data)


def _oaep():
    """Internal helper: OAEP padding adds randomness so RSA is secure.
    Without padding, identical messages would produce identical ciphertext."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def rsa_encrypt(public_key, data):
    """Lock data with a public key. Limited to ~190 bytes, so we only use
    this for AES keys, never for full messages."""
    return public_key.encrypt(data, _oaep())


def rsa_decrypt(private_key, data):
    """Unlock data using the matching private key."""
    return private_key.decrypt(data, _oaep())


# ---------------------------------------------------------------- AES ----

def generate_aes_key():
    """Create a random 256-bit AES key (used once per message)."""
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(key, plaintext):
    """Encrypt and authenticate data with AES-GCM.

    A fresh random 12-byte nonce is generated for every message so the same
    plaintext never produces the same ciphertext. The nonce is not secret,
    so it is attached to the front of the output.
    """
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def aes_decrypt(key, blob):
    """Split off the nonce, then decrypt. Raises InvalidTag if the data was
    modified in any way, which protects against tampering."""
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)