"""
TrySentry — Event Bus
Simple thread-safe pub/sub for internal events.
"""
import queue
import threading
from typing import Callable, List


class EventBus:
    def __init__(self):
        self._subscribers: dict[str, List[Callable]] = {}
        self._queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._running = False
        self._worker = None

    # ─── subscribe ───
    def subscribe(self, topic: str, callback: Callable):
        with self._lock:
            self._subscribers.setdefault(topic, []).append(callback)

    # ─── publish ───
    def publish(self, topic: str, data):
        self._queue.put((topic, data))

    # ─── dispatch loop ───
    def _dispatch_loop(self):
        while self._running:
            try:
                topic, data = self._queue.get(timeout=1)
            except queue.Empty:
                continue

            with self._lock:
                callbacks = list(self._subscribers.get(topic, []))
                wildcards = list(self._subscribers.get("*", []))

            for cb in callbacks + wildcards:
                try:
                    cb(topic, data)
                except Exception:
                    pass

    def start(self):
        if self._running:
            return
        self._running = True
        self._worker = threading.Thread(
            target=self._dispatch_loop, daemon=True
        )
        self._worker.start()

    def stop(self):
        self._running = False
        if self._worker:
            self._worker.join(timeout=2)
