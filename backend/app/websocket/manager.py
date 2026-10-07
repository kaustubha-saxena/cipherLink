from collections import defaultdict

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.rooms: dict[str, set[WebSocket]] = defaultdict(set)
        self.last_sequences: dict[str, dict[str, int]] = defaultdict(dict)
        self.key_exchange_seen: dict[str, set[str]] = defaultdict(set)

    async def connect(self, room_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.rooms[room_id].add(websocket)

    def disconnect(self, room_id: str, websocket: WebSocket) -> None:
        sockets = self.rooms.get(room_id)
        if sockets:
            sockets.discard(websocket)
            if not sockets:
                self.rooms.pop(room_id, None)
                self.last_sequences.pop(room_id, None)
                self.key_exchange_seen.pop(room_id, None)

    async def broadcast(self, room_id: str, payload: dict) -> None:
        for socket in list(self.rooms.get(room_id, set())):
            try:
                await socket.send_json(payload)
            except Exception:
                self.disconnect(room_id, socket)

    def accept_sequence(self, room_id: str, participant_id: str, sequence: int) -> bool:
        last_sequence = self.last_sequences[room_id].get(participant_id, 0)
        if sequence <= last_sequence:
            return False
        self.last_sequences[room_id][participant_id] = sequence
        return True

    def record_key_exchange(self, room_id: str, participant_id: str) -> tuple[bool, bool]:
        participants = self.key_exchange_seen[room_id]
        if participant_id in participants:
            return False, len(participants) == 2
        participants.add(participant_id)
        return True, len(participants) == 2


manager = ConnectionManager()

