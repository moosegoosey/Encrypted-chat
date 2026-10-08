"""
server.py - WebSocket relay server for the encrypted chat app.

The server is intentionally "dumb": it accepts connections and forwards each
message to every other connected client. It never inspects or modifies the
message contents, so once clients encrypt their messages, the server only
ever sees ciphertext and cannot read the conversation.
"""

import asyncio
from websockets.asyncio.server import serve

# Every client that is currently connected. A set avoids duplicates.
clients = set()


async def handler(websocket):
    """Runs once per connected client, for as long as that client stays connected."""
    clients.add(websocket)
    print(f"Client connected. Total: {len(clients)}")
    try:
        # Wait for each incoming message from this client.
        async for message in websocket:
            # Relay the message to everyone except the sender.
            for other in clients:
                if other is not websocket:
                    await other.send(message)
    finally:
        # Always runs, even if the client crashes, so we never keep dead connections.
        clients.remove(websocket)
        print(f"Client disconnected. Total: {len(clients)}")


async def main():
    # Listen on this machine only (localhost), port 8765.
    async with serve(handler, "localhost", 8765):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # Wait forever so the server keeps running.


asyncio.run(main())