"""
TrySentry - Attack timeline
Builds a chronological view of alerts + events.
"""
import time
from typing import List

from .. import logger


def build(alerts: List[dict]) -> List[dict]:
    """Sort alerts by time and return a timeline."""
    entries = []
    for a in alerts:
        entries.append({
            "time": a.get("_stored_at", time.time()),
            "severity": a.get("severity", "low"),
            "title": a.get("title", ""),
            "mitre": a.get("mitre", {}).get("id", ""),
            "process": a.get("event", {}).get("Image", ""),
        })
    entries.sort(key=lambda x: x["time"])
    return entries


def print_timeline(alerts: List[dict]):
    entries = build(alerts)
    if not entries:
        logger.info("Timeline is empty")
        return

    logger.line()
    for e in entries:
        t = time.strftime("%H:%M:%S", time.localtime(e["time"]))
        logger.console.print(
            f"[bright_blue]{t}[/bright_blue]  "
            f"[white]{e['severity'].upper():<8}[/white]  "
            f"[white]{e['title']}[/white]  "
            f"[bright_blue]{e['mitre']}[/bright_blue]"
        )
    logger.line()
