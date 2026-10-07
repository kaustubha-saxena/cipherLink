import hashlib
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    def __init__(self):
        self.attempts: dict[str, deque[float]] = defaultdict(deque)
        self.last_logged: dict[str, float] = {}

    def consume(self, key: str, limit: int, window_seconds: int = 60) -> tuple[int, bool]:
        now = time.monotonic()
        attempts = self.attempts[key]
        while attempts and now - attempts[0] >= window_seconds:
            attempts.popleft()

        if len(attempts) >= limit:
            should_log = now - self.last_logged.get(key, 0) >= window_seconds
            if should_log:
                self.last_logged[key] = now
            return max(1, int(window_seconds - (now - attempts[0]))), should_log

        attempts.append(now)
        return 0, False


def anonymize_address(address: str) -> str:
    return hashlib.sha256(address.encode("utf-8")).hexdigest()[:16]


limiter = SlidingWindowRateLimiter()
