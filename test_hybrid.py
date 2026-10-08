"""
test_hybrid.py - Manual test for hybrid (RSA + AES) encryption.

Proves that:
  1. A message too large for RSA alone can be sent using AES + RSA together.
  2. AES-GCM detects tampering with the encrypted data.
"""

from crypto_utils import *

private_key, public_key = generate_keypair()

message = b"x" * 300  # Too large for RSA alone (limit is ~190 bytes).

# --- Sender side ---
aes_key = generate_aes_key()                        # Random one-time key
encrypted_message = aes_encrypt(aes_key, message)   # AES encrypts the message
encrypted_key = rsa_encrypt(public_key, aes_key)    # RSA locks the AES key

# --- Recipient side ---
recovered_key = rsa_decrypt(private_key, encrypted_key)  # RSA unlocks the AES key
print(aes_decrypt(recovered_key, encrypted_message) == message)  # Expect True

# --- Tamper test: flip one bit and confirm decryption is rejected ---
tampered = bytearray(encrypted_message)
tampered[20] ^= 1
try:
    aes_decrypt(recovered_key, bytes(tampered))
except Exception as e:
    print("Tampering detected:", type(e).__name__)  # Expect InvalidTag