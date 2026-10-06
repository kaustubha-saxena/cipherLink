from collections import defaultdict

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.rooms: dict[str, set[WebSocket]] = defaultdict(set)

    async def connect(self, room_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.rooms[room_id].add(websocket)

    def disconnect(self, room_id: str, websocket: WebSocket) -> None:
        sockets = self.rooms.get(room_id)
        if sockets:
            sockets.discard(websocket)
            if not sockets:
                self.rooms.pop(room_id, None)

    async def broadcast(self, room_id: str, payload: dict) -> None:
        for socket in list(self.rooms.get(room_id, set())):
            try:
                await socket.send_json(payload)
            except Exception:
                self.disconnect(room_id, socket)


manager = ConnectionManager()

