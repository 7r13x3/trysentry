"""
TrySentry — State tracker
Keeps track of running process tree, alerts, behavioral chains.
"""
import time
from collections import deque
from typing import List, Dict, Optional


class ProcessNode:
    def __init__(self, pid: int, ppid: int, name: str, cmdline: str = ""):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.cmdline = cmdline
        self.first_seen = time.time()


class State:
    def __init__(self, max_alerts: int = 10000,
                 correlation_window: int = 10):
        self.processes: Dict[int, ProcessNode] = {}
        self.alerts: deque = deque(maxlen=max_alerts)
        self.correlation_window = correlation_window
        self.start_time = time.time()
        self.events_seen = 0
        self.alerts_count = 0

    # ─── processes ───
    def add_process(self, info: dict):
        self.processes[info["pid"]] = ProcessNode(
            info["pid"],
            info.get("ppid", 0),
            info.get("name", ""),
            info.get("cmdline", ""),
        )

    def remove_process(self, pid: int):
        self.processes.pop(pid, None)

    def get_process(self, pid: int) -> Optional[ProcessNode]:
        return self.processes.get(pid)

    def get_parent(self, pid: int) -> Optional[ProcessNode]:
        proc = self.processes.get(pid)
        if not proc:
            return None
        return self.processes.get(proc.ppid)

    def process_chain(self, pid: int, max_depth: int = 8) -> List[str]:
        """Return [parent, parent-of-parent, ...] for a PID."""
        chain = []
        current = pid
        for _ in range(max_depth):
            proc = self.processes.get(current)
            if not proc:
                break
            chain.append(proc.name)
            if proc.ppid == 0 or proc.ppid == current:
                break
            current = proc.ppid
        return chain

    # ─── alerts ───
    def add_alert(self, alert: dict):
        alert["_stored_at"] = time.time()
        self.alerts.append(alert)
        self.alerts_count += 1

    def recent_alerts(self, n: int = 20) -> List[dict]:
        return list(self.alerts)[-n:]

    def alerts_by_severity(self) -> Dict[str, int]:
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in self.alerts:
            sev = a.get("severity", "low")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    # ─── stats ───
    def uptime_seconds(self) -> float:
        return time.time() - self.start_time

    def stats(self) -> dict:
        return {
            "processes_tracked": len(self.processes),
            "events_seen": self.events_seen,
            "alerts_total": self.alerts_count,
            "uptime": self.uptime_seconds(),
            "by_severity": self.alerts_by_severity(),
        }
