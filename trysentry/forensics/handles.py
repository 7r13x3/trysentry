"""
TrySentry - Handle enumeration
Lists open files, sockets, and pipes held by a process.
"""
import psutil
from .. import logger


def list_handles(pid: int) -> dict:
    """Return open files + sockets for a PID."""
    result = {"files": [], "sockets": [], "pipes": []}
    try:
        proc = psutil.Process(pid)
        for f in proc.open_files():
            result["files"].append({
                "path": f.path,
                "mode": f.mode,
            })
        for c in proc.connections(kind="inet"):
            result["sockets"].append({
                "laddr": f"{c.laddr.ip}:{c.laddr.port}",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
                "status": c.status,
            })
    except psutil.NoSuchProcess:
        logger.warn(f"PID {pid} not found")
    except psutil.AccessDenied:
        logger.warn(f"Access denied for PID {pid} - run as Admin")
    except Exception as e:
        logger.warn(f"Handle enum failed: {e}")
    return result


def print_handles(pid: int):
    h = list_handles(pid)

    if h["files"]:
        rows = [[f["mode"], f["path"][-70:]] for f in h["files"][:30]]
        logger.table(f"Open Files - PID {pid}", ["Mode", "Path"], rows)

    if h["sockets"]:
        rows = [[c["laddr"], c["raddr"], c["status"]]
                for c in h["sockets"][:30]]
        logger.table(f"Open Sockets - PID {pid}",
                     ["Local", "Remote", "Status"], rows)
