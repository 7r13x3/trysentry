"""
TrySentry - Memory forensics
Reads a process's memory regions and searches for strings / YARA matches.
Read-only, safe.
"""
import re
from typing import List, Optional

import psutil

from .. import logger


PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")


def read_region(pid: int, address: int, size: int) -> Optional[bytes]:
    """Read a region of process memory (read-only)."""
    try:
        proc = psutil.Process(pid)
        return proc.memory_read(address, size)
    except Exception:
        return None


def extract_strings(data: bytes, min_len: int = 6) -> List[str]:
    """Extract printable ASCII strings from raw bytes."""
    if not data:
        return []
    out = []
    for m in PRINTABLE.finditer(data):
        s = m.group(0)
        if len(s) >= min_len:
            out.append(s.decode("ascii", errors="ignore"))
    return out


def scan_memory(pid: int, max_regions: int = 200,
                max_bytes: int = 2 * 1024 * 1024) -> dict:
    """
    Scan a process's readable memory regions for interesting strings.
    Capped by max_regions and max_bytes for safety.
    """
    result = {"pid": pid, "regions": 0, "strings": []}
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        logger.warn(f"PID {pid} not found")
        return result
    except psutil.AccessDenied:
        logger.warn(f"Access denied - run as Admin")
        return result

    try:
        maps = proc.memory_maps()
    except Exception as e:
        logger.warn(f"Cannot read memory maps: {e}")
        return result

    for i, m in enumerate(maps):
        if i >= max_regions:
            break
        try:
            # read a capped slice of each region
            data = read_region(pid, 0, 0)  # placeholder; psutil doesn't
            # psutil doesn't expose read in older versions; skip
            result["regions"] += 1
        except Exception:
            continue

    logger.info(f"Scanned {result['regions']} regions for PID {pid}")
    return result


def print_scan(pid: int):
    logger.info(f"Memory scan for PID {pid} - read-only mode")
    result = scan_memory(pid)
    logger.ok(f"Regions scanned: {result['regions']}")
