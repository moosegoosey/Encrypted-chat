"""
test_keys.py - Manual test for the RSA functions.

Simulates what happens in the real app: generate a key pair, send the public
key as bytes, lock a message with it, and unlock it with the private key.
"""

from crypto_utils import *

private_key, public_key = generate_keypair()

# Simulate sending the public key over the network and rebuilding it.
sent = public_key_to_bytes(public_key)
print(sent.decode())
received_key = public_key_from_bytes(sent)

# Lock with the public key, unlock with the private key.
locked = rsa_encrypt(received_key, b"hello bob")
print("Locked:", locked.hex()[:60], "...")
print("Unlocked:", rsa_decrypt(private_key, locked))

# Experiment: change the message to b"x" * 300 to see RSA fail on large data.