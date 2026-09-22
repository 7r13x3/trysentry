"""
TrySentry — Process Monitor
Polls running processes and detects new ones.
Falls back to user-mode telemetry when Sysmon is not available.
"""
import time
import threading
from typing import Dict, Set

import psutil

from .. import logger


class ProcessMonitor:
    def __init__(self, bus, cfg):
        self.bus = bus
        self.cfg = cfg
        self._running = False
        self._thread = None
        self._known: Dict[int, dict] = {}

    def _snapshot(self) -> Dict[int, dict]:
        procs = {}
        for p in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username",
             "create_time", "cpu_percent", "memory_info"]
        ):
            try:
                info = p.info
                procs[p.pid] = {
                    "pid": p.pid,
                    "ppid": info.get("ppid"),
                    "name": info.get("name") or "",
                    "exe": info.get("exe") or "",
                    "cmdline": " ".join(info.get("cmdline") or []),
                    "user": info.get("username") or "",
                    "create_time": info.get("create_time") or 0,
                    "memory": info.get("memory_info").rss
                    if info.get("memory_info") else 0,
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return procs

    def _loop(self):
        # initial snapshot
        self._known = self._snapshot()
        logger.ok(f"Process monitor: tracking {len(self._known)} processes")

        while self._running:
            time.sleep(self.cfg.engine.interval_ms / 1000.0)
            current = self._snapshot()

            # new processes
            for pid, info in current.items():
                if pid not in self._known:
                    self.bus.publish("process.new", info)

            # terminated processes
            for pid in list(self._known.keys()):
                if pid not in current:
                    self.bus.publish("process.exit",
                                     {"pid": pid,
                                      "name": self._known[pid]["name"]})

            self._known = current

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
