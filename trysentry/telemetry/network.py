"""
TrySentry — Network Monitor
Tracks outbound connections and detects new ones.
"""
import time
import threading
from typing import Set

import psutil

from .. import logger


class NetworkMonitor:
    def __init__(self, bus, cfg):
        self.bus = bus
        self.cfg = cfg
        self._running = False
        self._thread = None
        self._seen: Set[str] = set()

    def _conn_key(self, c) -> str:
        return f"{c.laddr.ip}:{c.laddr.port}->{c.raddr.ip}:{c.raddr.port}"

    def _loop(self):
        logger.ok("Network monitor: starting")
        while self._running:
            try:
                conns = psutil.net_connections(kind="inet")
            except (psutil.AccessDenied, PermissionError):
                time.sleep(2)
                continue

            for c in conns:
                if not c.raddr:
                    continue
                if c.status != psutil.CONN_ESTABLISHED:
                    continue

                key = self._conn_key(c)
                if key in self._seen:
                    continue
                self._seen.add(key)

                # resolve process name
                pname = ""
                try:
                    if c.pid:
                        pname = psutil.Process(c.pid).name()
                except Exception:
                    pass

                self.bus.publish("network.new", {
                    "pid": c.pid,
                    "process": pname,
                    "local": f"{c.laddr.ip}:{c.laddr.port}",
                    "remote_ip": c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "status": c.status,
                })

            # trim seen set occasionally
            if len(self._seen) > 50000:
                self._seen = set(list(self._seen)[-10000:])

            time.sleep(self.cfg.engine.interval_ms / 1000.0)

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
