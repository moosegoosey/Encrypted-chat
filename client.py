"""
client.py - End-to-end encrypted command-line chat client.

On startup each client generates an RSA key pair and swaps public keys with
the other user through the relay server. Every message is then encrypted
with a fresh AES key, and that AES key is locked with the recipient's public
key (hybrid encryption). The server only ever sees ciphertext.
"""

import asyncio
import base64
import json

from websockets.asyncio.client import connect

from crypto_utils import (
    generate_keypair, public_key_to_bytes, public_key_from_bytes,
    rsa_encrypt, rsa_decrypt,
    generate_aes_key, aes_encrypt, aes_decrypt,
)


def b64e(data):
    """bytes -> text, so binary data can travel inside a JSON packet."""
    return base64.b64encode(data).decode()


def b64d(text):
    """text -> bytes (the reverse of b64e)."""
    return base64.b64decode(text)


async def send_public_key(websocket, state):
    """Send our public key to the other user (via the server)."""
    packet = {"type": "pubkey", "key": b64e(state["my_public_bytes"])}
    await websocket.send(json.dumps(packet))


async def receive(websocket, state):
    """Background task: handle every packet that arrives from the server."""
    async for raw in websocket:
        packet = json.loads(raw)

        if packet["type"] == "pubkey":
            key_bytes = b64d(packet["key"])
            # Only act if this is a new or changed key (prevents endless replies).
            if key_bytes != state["peer_bytes"]:
                state["peer_bytes"] = key_bytes
                state["peer_key"] = public_key_from_bytes(key_bytes)
                print("\n[Secure channel ready: received the other user's public key]")
                # Reply with our key so they have ours too, even if they
                # connected after we sent it the first time.
                await send_public_key(websocket, state)

        elif packet["type"] == "msg":
            try:
                # 1. Unlock the AES key using OUR private key.
                aes_key = rsa_decrypt(state["private_key"], b64d(packet["key"]))
                # 2. Use the AES key to decrypt the actual message.
                text = aes_decrypt(aes_key, b64d(packet["data"])).decode()
                print(f"\nThem: {text}")
            except Exception:
                print("\n[Warning: received a message that failed to decrypt]")


async def main():
    # Generate this session's key pair. The private key stays in memory only.
    private_key, public_key = generate_keypair()
    state = {
        "private_key": private_key,
        "my_public_bytes": public_key_to_bytes(public_key),
        "peer_key": None,     # the other user's public key (once received)
        "peer_bytes": None,   # raw bytes of it, used to detect changes
    }

    async with connect("ws://localhost:8765") as websocket:
        asyncio.create_task(receive(websocket, state))
        await send_public_key(websocket, state)  # announce ourselves

        while True:
            text = await asyncio.to_thread(input, "You: ")

            if state["peer_key"] is None:
                print("[Waiting for the other user to connect...]")
                continue

            # Hybrid encryption: AES for the message, RSA for the AES key.
            aes_key = generate_aes_key()
            packet = {
                "type": "msg",
                "key": b64e(rsa_encrypt(state["peer_key"], aes_key)),
                "data": b64e(aes_encrypt(aes_key, text.encode())),
            }
            await websocket.send(json.dumps(packet))


asyncio.run(main())