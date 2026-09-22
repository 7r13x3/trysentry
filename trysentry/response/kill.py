"""
TrySentry — Process termination
Safely kills a process tree, respecting the whitelist.
"""
import time
from typing import Optional

import psutil

from .. import logger


# Absolute minimum — never kill these or Windows will crash
CRITICAL = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
    "fontdrvhost.exe", "dwm.exe", "memory compression",
}


class KillResult:
    def __init__(self):
        self.killed = []
        self.failed = []
        self.skipped = []

    def summary(self) -> str:
        return (f"killed={len(self.killed)} "
                f"failed={len(self.failed)} "
                f"skipped={len(self.skipped)}")


def _is_critical(name: str) -> bool:
    return name.lower() in CRITICAL


def kill_tree(pid: int, cfg, dry_run: bool = False) -> KillResult:
    """
    Kill a process and all its children.
    Respects whitelist and critical process list.
    """
    result = KillResult()

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        logger.warn(f"PID {pid} no longer exists")
        return result

    # check whitelist
    pname = proc.name()
    if pname in cfg.whitelist.processes:
        logger.warn(f"Refusing to kill whitelisted process: {pname} (PID {pid})")
        result.skipped.append(pid)
        return result

    if _is_critical(pname):
        logger.warn(f"Refusing to kill critical process: {pname} (PID {pid})")
        result.skipped.append(pid)
        return result

    # get children first (recursive)
    try:
        children = proc.children(recursive=True)
    except psutil.NoSuchProcess:
        children = []

    # kill children first, then the parent
    for child in children:
        _try_kill(child, result, dry_run)

    _try_kill(proc, result, dry_run)
    return result


def _try_kill(proc: psutil.Process, result: KillResult, dry_run: bool):
    try:
        name = proc.name()
        pid = proc.pid

        if _is_critical(name):
            result.skipped.append(pid)
            return

        if dry_run:
            logger.info(f"[DRY RUN] Would kill {name} (PID {pid})")
            result.killed.append(pid)
            return

        proc.terminate()
        try:
            proc.wait(timeout=2)
        except psutil.TimeoutExpired:
            proc.kill()

        logger.alert(f"Killed {name} (PID {pid})")
        result.killed.append(pid)

    except psutil.NoSuchProcess:
        result.skipped.append(proc.pid)
    except psutil.AccessDenied:
        logger.warn(f"Access denied killing PID {proc.pid} — run as Admin")
        result.failed.append(proc.pid)
    except Exception as e:
        logger.warn(f"Kill failed for PID {proc.pid}: {e}")
        result.failed.append(proc.pid)
