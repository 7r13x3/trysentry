"""
TrySentry — Sysmon Event Log Reader
Reads Microsoft-Windows-Sysmon/Operational via pywin32 EvtSubscribe.
Falls back gracefully if Sysmon or pywin32 is not available.
"""
import threading
import time
from xml.etree import ElementTree as ET

from .. import logger

try:
    import win32evtlog
    import win32evtlogutil
    import win32event
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


# Sysmon event IDs we care about
EVENT_NAMES = {
    1:  "process_create",
    3:  "network_connect",
    7:  "image_load",
    8:  "remote_thread",
    10: "process_access",
    11: "file_create",
    12: "registry_create_delete",
    13: "registry_set",
    19: "wmi_filter",
    20: "wmi_consumer",
    22: "dns_query",
}


def _parse_sysmon_xml(xml_str: str) -> dict:
    """Convert Sysmon event XML into a flat dict."""
    out = {}
    try:
        root = ET.fromstring(xml_str)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        # event id
        eid_el = root.find("e:System/e:EventID", ns)
        if eid_el is not None:
            out["event_id"] = int(eid_el.text)
            out["event_name"] = EVENT_NAMES.get(out["event_id"], "unknown")

        # timestamp
        t_el = root.find("e:System/e:TimeCreated", ns)
        if t_el is not None:
            out["timestamp"] = t_el.attrib.get("SystemTime", "")

        # computer
        c_el = root.find("e:System/e:Computer", ns)
        if c_el is not None:
            out["computer"] = c_el.text

        # event data — flat key/value pairs
        for d in root.iter(
            "{http://schemas.microsoft.com/win/2004/08/events/event}Data"
        ):
            name = d.attrib.get("Name")
            if name:
                out[name] = (d.text or "").strip()

    except Exception:
        pass

    return out


class SysmonReader:
    """
    Reads Sysmon events from the Windows Event Log.

    Uses polling (ReadEventLog style via win32evtlog).
    Requires Administrator privileges and Sysmon installed.
    """

    CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self, bus, cfg):
        self.bus = bus
        self.cfg = cfg
        self._running = False
        self._thread = None
        self._last_record = 0

    def _loop(self):
        if not HAS_PYWIN32:
            logger.warn("pywin32 not available — Sysmon reader disabled")
            return

        logger.ok(f"Sysmon reader: reading {self.CHANNEL}")
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, self.CHANNEL)
        except Exception as e:
            logger.warn(f"Cannot open Sysmon channel: {e}")
            logger.hint("Is Sysmon installed? Run: sc query sysmon64")
            return

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        try:
            while self._running:
                try:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                except Exception:
                    events = []

                if not events:
                    time.sleep(0.5)
                    continue

                for ev in events:
                    try:
                        rec = ev.RecordNumber
                        if rec <= self._last_record:
                            continue
                        self._last_record = rec

                        xml_str = ev.StringInserts[0] if ev.StringInserts \
                            else ""
                        parsed = _parse_sysmon_xml(xml_str)
                        if parsed:
                            self.bus.publish("sysmon.event", parsed)
                    except Exception:
                        continue

                time.sleep(0.2)
        finally:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass

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
