"""
client.py - Command-line chat client.

Connects to the relay server, prints incoming messages in the background,
and sends whatever the user types. (Encryption will be added in a later step.)
"""

import asyncio
from websockets.asyncio.client import connect


async def receive(websocket):
    """Background task: print every message that arrives from the server."""
    async for message in websocket:
        print(f"\nThem: {message}")


async def main():
    # Open a connection to the relay server.
    async with connect("ws://localhost:8765") as websocket:
        # Start listening in the background so we can receive while typing.
        asyncio.create_task(receive(websocket))

        while True:
            # input() blocks, so run it in a separate thread to keep
            # the background listener working while the user types.
            text = await asyncio.to_thread(input, "You: ")
            await websocket.send(text)


asyncio.run(main())