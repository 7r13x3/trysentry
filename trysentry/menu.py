"""
TrySentry — Interactive Menu
Blue & white theme.
"""
import os
import sys
import time
import threading

from . import logger
from .config import load
from .core.engine import Engine
from .core.state import State
from .response.quarantine import Quarantine
from .response import firewall


MENU_OPTIONS = [
    ("1",  "Start Monitoring"),
    ("2",  "Stop Monitoring"),
    ("3",  "View Alerts"),
    ("4",  "View Timeline"),
    ("5",  "Forensics Snapshot"),
    ("6",  "Load Rules"),
    ("7",  "Scan Memory (YARA)"),
    ("8",  "Launch Dashboard"),
    ("9",  "Generate Report"),
    ("10", "Show Firewall Blocks"),
    ("11", "Show Quarantine Vault"),
    ("12", "Settings"),
    ("0",  "Exit"),
]


_engine = None
_engine_thread = None


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def _is_running() -> bool:
    global _engine
    return _engine is not None and _engine._running


def show_status(config_path: str):
    try:
        cfg = load(config_path)
    except Exception:
        cfg = None

    logger.line()
    if _is_running():
        logger.console.print(f"[bright_blue]  ENGINE:[/bright_blue]     "
                             f"[white]RUNNING[/white]")
    else:
        logger.console.print(f"[bright_blue]  ENGINE:[/bright_blue]     "
                             f"[white]STOPPED[/white]")

    if cfg:
        logger.console.print(f"[bright_blue]  SYSMON:[/bright_blue]     "
                             f"[white]{cfg.telemetry.use_sysmon}[/white]")
        logger.console.print(f"[bright_blue]  AUTO-RESP:[/bright_blue]  "
                             f"[white]{cfg.response.auto_response}[/white]")
        logger.console.print(f"[bright_blue]  MIN SEV:[/bright_blue]    "
                             f"[white]{cfg.alerts.min_severity}[/white]")

    logger.line()


# ─────────────────────────────────────────────
#  Actions
# ─────────────────────────────────────────────

def action_start(config_path: str):
    global _engine, _engine_thread
    if _is_running():
        logger.warn("Engine is already running")
        return

    cfg = load(config_path)
    _engine = Engine(cfg)
    _engine_thread = threading.Thread(
        target=_engine.start, daemon=True
    )
    _engine_thread.start()
    logger.ok("Engine started in background")
    logger.hint("Use option 3 to view alerts, option 2 to stop")


def action_stop():
    global _engine
    if not _is_running():
        logger.warn("Engine is not running")
        return
    _engine.stop()
    _engine = None
    logger.ok("Engine stopped")


def action_alerts():
    if not _is_running() or not _engine:
        logger.warn("Engine not running — start it first (option 1)")
        return
    alerts = _engine.state.recent_alerts(20)
    if not alerts:
        logger.info("No alerts yet")
        return

    rows = []
    for a in alerts:
        mitre = a.get("mitre", {})
        rows.append([
            a.get("severity", "low"),
            a.get("score", 0),
            a.get("title", "")[:40],
            mitre.get("id", ""),
        ])

    logger.table(
        "Recent Alerts",
        ["Severity", "Score", "Rule", "MITRE"],
        rows,
    )


def action_timeline():
    if not _is_running() or not _engine:
        logger.warn("Engine not running")
        return

    alerts = _engine.state.recent_alerts(50)
    if not alerts:
        logger.info("No timeline entries")
        return

    logger.line()
    for a in alerts:
        sev = a.get("severity", "low").upper()
        t = time.strftime("%H:%M:%S",
                          time.localtime(a.get("_stored_at", time.time())))
        logger.console.print(
            f"[bright_blue]{t}[/bright_blue]  "
            f"[white]{sev:<8}[/white]  "
            f"[white]{a.get('title', '')}[/white]"
        )
    logger.line()


def action_snapshot():
    if not _is_running() or not _engine:
        logger.warn("Engine not running")
        return

    import json
    from pathlib import Path
    out_dir = Path("logs")
    out_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = out_dir / f"snapshot_{ts}.json"

    stats = _engine.state.stats()
    processes = [
        {"pid": p.pid, "ppid": p.ppid, "name": p.name,
         "cmdline": p.cmdline[:200]}
        for p in list(_engine.state.processes.values())[:200]
    ]

    data = {"stats": stats, "processes": processes,
            "generated_at": time.time()}
    out.write_text(json.dumps(data, indent=2, default=str))
    logger.ok(f"Forensic snapshot saved: {out}")


def action_load_rules(config_path: str):
    try:
        cfg = load(config_path)
        from .detection.sigma import SigmaEngine
        engine = SigmaEngine(cfg.detection.sigma_dir)
        n = engine.load()
        logger.ok(f"Loaded {n} rules")
    except Exception as e:
        logger.warn(f"Failed to load rules: {e}")


def action_scan_memory():
    logger.info("YARA memory scan — coming in next batch")


def action_dashboard():
    logger.info("Dashboard — coming in next batch")


def action_report():
    logger.info("Report generation — coming in next batch")


def action_firewall():
    blocked = firewall.list_blocked()
    if not blocked:
        logger.info("No IPs currently blocked by TrySentry")
        return

    rows = [[i + 1, ip] for i, ip in enumerate(blocked)]
    logger.table("Firewall Blocks", ["#", "IP"], rows)


def action_quarantine():
    q = Quarantine("quarantine")
    entries = q.list_entries()
    if not entries:
        logger.info("Quarantine vault is empty")
        return

    rows = []
    for e in entries:
        t = time.strftime("%Y-%m-%d %H:%M",
                          time.localtime(e.get("at", 0)))
        rows.append([e.get("id", ""), t, e.get("reason", "")[:40]])
    logger.table("Quarantine Vault", ["ID", "Date", "Reason"], rows)


def action_settings(config_path: str):
    try:
        cfg = load(config_path)
    except Exception as e:
        logger.warn(f"Cannot load config: {e}")
        return

    logger.panel("Configuration", (
        f"Config file:       {config_path}\n"
        f"Sysmon enabled:    {cfg.telemetry.use_sysmon}\n"
        f"Auto-response:     {cfg.response.auto_response}\n"
        f"Kill threshold:    {cfg.response.kill_threshold}\n"
        f"Quarantine:        {cfg.response.quarantine_threshold}\n"
        f"Firewall:          {cfg.response.firewall_threshold}\n"
        f"Min severity:      {cfg.alerts.min_severity}\n"
        f"Sigma rules dir:   {cfg.detection.sigma_dir}\n"
    ))


# ─────────────────────────────────────────────
#  Dispatcher
# ─────────────────────────────────────────────

def handle_choice(choice: str, config_path: str):
    if choice == "0":
        if _is_running():
            action_stop()
        logger.info("Goodbye.")
        sys.exit(0)
    elif choice == "1":
        action_start(config_path)
    elif choice == "2":
        action_stop()
    elif choice == "3":
        action_alerts()
    elif choice == "4":
        action_timeline()
    elif choice == "5":
        action_snapshot()
    elif choice == "6":
        action_load_rules(config_path)
    elif choice == "7":
        action_scan_memory()
    elif choice == "8":
        action_dashboard()
    elif choice == "9":
        action_report()
    elif choice == "10":
        action_firewall()
    elif choice == "11":
        action_quarantine()
    elif choice == "12":
        action_settings(config_path)
    else:
        logger.warn(f"Unknown option: {choice}")


def run(config_path: str = "configs/example.toml"):
    while True:
        clear()
        logger.banner()
        show_status(config_path)
        logger.menu("MAIN MENU", MENU_OPTIONS)

        try:
            choice = input("Choose [0-12]: ").strip()
        except (KeyboardInterrupt, EOFError):
            if _is_running():
                action_stop()
            logger.info("Goodbye.")
            sys.exit(0)

        handle_choice(choice, config_path)

        if choice != "0":
            input("\nPress Enter to return to menu...")
