import asyncio
from websockets.asyncio.server import serve

clients = set()  # every currently connected client

async def handler(websocket):
    clients.add(websocket)
    print(f"Client connected. Total: {len(clients)}")
    try:
        async for message in websocket:
            # relay to everyone except the sender
            for other in clients:
                if other is not websocket:
                    await other.send(message)
    finally:
        clients.remove(websocket)
        print(f"Client disconnected. Total: {len(clients)}")

async def main():
    async with serve(handler, "localhost", 8765):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # run forever

asyncio.run(main())