import asyncio
from websockets.asyncio.client import connect

async def receive(websocket):
    async for message in websocket:
        print(f"\nThem: {message}")

async def main():
    async with connect("ws://localhost:8765") as websocket:
        asyncio.create_task(receive(websocket))
        while True:
            text = await asyncio.to_thread(input, "You: ")
            await websocket.send(text)

asyncio.run(main())