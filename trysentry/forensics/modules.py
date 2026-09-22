"""
TrySentry - Module enumeration
Lists loaded DLLs for a process.
"""
import psutil
from .. import logger


def list_modules(pid: int) -> list:
    """Return the list of loaded modules for a PID."""
    out = []
    try:
        proc = psutil.Process(pid)
        for m in proc.memory_maps():
            out.append({
                "path": m.path,
                "rss": m.rss,
                "size": m.size,
            })
    except psutil.NoSuchProcess:
        logger.warn(f"PID {pid} not found")
    except psutil.AccessDenied:
        logger.warn(f"Access denied for PID {pid} - run as Admin")
    except Exception as e:
        logger.warn(f"Module enum failed: {e}")
    return out


def print_modules(pid: int):
    """Pretty-print the modules of a process."""
    mods = list_modules(pid)
    if not mods:
        return

    rows = []
    for m in mods[:100]:
        rows.append([m["path"][-70:], m["size"]])

    logger.table(f"Modules - PID {pid}",
                 ["Path", "Size (bytes)"], rows)
