"""
TrySentry — CLI entry point
"""
import argparse
import sys
import time

from .config import load
from .core.engine import Engine
from . import logger
from . import __version__


def cmd_start(args):
    cfg = load(args.config)
    engine = Engine(cfg)
    try:
        engine.start()
    except KeyboardInterrupt:
        logger.info("Stopped by user")


def cmd_check(args):
    try:
        cfg = load(args.config)
    except Exception as e:
        logger.error(f"Config error: {e}")
        sys.exit(1)

    logger.success_config(cfg)


def cmd_rules(args):
    cfg = load(args.config)
    from .detection.sigma import SigmaEngine
    engine = SigmaEngine(cfg.detection.sigma_dir)
    n = engine.load()
    logger.ok(f"Loaded {n} rules from {cfg.detection.sigma_dir}")

    for r in engine.rules:
        mitre = r.mitre_id or "-"
        logger.console.print(
            f"  [{r.level:<8}] {r.title}  ({mitre})"
        )


def cmd_gui(args):
    from .menu import run
    run(args.config)


def cmd_report(args):
    logger.info("Report — coming in next batch")


def main():
    parser = argparse.ArgumentParser(
        prog="trysentry",
        description="TrySentry — Endpoint Detection & Response",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_start = sub.add_parser("start", help="Start monitoring")
    p_start.add_argument("--config", "-c",
                         default="configs/example.toml")
    p_start.set_defaults(func=cmd_start)

    p_check = sub.add_parser("check", help="Validate config")
    p_check.add_argument("--config", "-c",
                         default="configs/example.toml")
    p_check.set_defaults(func=cmd_check)

    p_rules = sub.add_parser("rules", help="List loaded rules")
    p_rules.add_argument("--config", "-c",
                         default="configs/example.toml")
    p_rules.set_defaults(func=cmd_rules)

    p_gui = sub.add_parser("gui", help="Launch interactive menu")
    p_gui.add_argument("--config", "-c",
                       default="configs/example.toml")
    p_gui.set_defaults(func=cmd_gui)

    p_report = sub.add_parser("report", help="Generate HTML report")
    p_report.add_argument("--config", "-c",
                          default="configs/example.toml")
    p_report.add_argument("--output", "-o", default="report.html")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
