"""
TrySentry — Main engine
Wires telemetry → pipeline → response into one runnable loop.
"""
import threading
import time
import sys

from .. import logger
from .event_bus import EventBus
from .state import State
from .pipeline import Pipeline
from ..telemetry import processes, network, sysmon


class Engine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.bus = EventBus()
        self.state = State(
            max_alerts=cfg.engine.max_alerts_buffer,
            correlation_window=cfg.engine.correlation_window,
        )
        self.pipeline = Pipeline(cfg, self.state)
        self._monitors = []
        self._running = False
        self._stats_thread = None

    # ─────────────────────────────────────────────
    def _build_monitors(self):
        t = self.cfg.telemetry

        if t.use_sysmon:
            self._monitors.append(sysmon.SysmonReader(self.bus, self.cfg))

        if t.use_processes:
            self._monitors.append(
                processes.ProcessMonitor(self.bus, self.cfg)
            )

        if t.use_network:
            self._monitors.append(
                network.NetworkMonitor(self.bus, self.cfg)
            )

    # ─────────────────────────────────────────────
    def _stats_loop(self):
        while self._running:
            time.sleep(30)
            s = self.state.stats()
            logger.info(
                f"stats: procs={s['processes_tracked']} "
                f"events={s['events_seen']} "
                f"alerts={s['alerts_total']} "
                f"uptime={int(s['uptime'])}s"
            )

    # ─────────────────────────────────────────────
    def start(self):
        logger.banner()
        logger.info("Starting TrySentry engine...")

        # wire pipeline to bus
        self.bus.subscribe("*", self.pipeline.handle)
        self.bus.start()

        # build + start monitors
        self._build_monitors()
        for m in self._monitors:
            try:
                m.start()
            except Exception as e:
                logger.warn(f"Monitor failed to start: {e}")

        self._running = True
        self._stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True
        )
        self._stats_thread.start()

        logger.ok(f"Engine running — {len(self._monitors)} monitors active")
        logger.hint("Press Ctrl+C to stop")

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping...")
            self.stop()

    # ─────────────────────────────────────────────
    def stop(self):
        self._running = False

        for m in self._monitors:
            try:
                m.stop()
            except Exception:
                pass

        self.bus.stop()

        s = self.state.stats()
        logger.line("═")
        logger.ok("TrySentry stopped")
        logger.info(f"Total events processed: {s['events_seen']}")
        logger.info(f"Total alerts generated: {s['alerts_total']}")
        sev = s["by_severity"]
        logger.info(f"By severity: low={sev['low']} "
                    f"medium={sev['medium']} "
                    f"high={sev['high']} "
                    f"critical={sev['critical']}")
        logger.info(f"Uptime: {int(s['uptime'])}s")

        # save alerts to JSON
        self._save_alerts()

    # ─────────────────────────────────────────────
    def _save_alerts(self):
        if not self.cfg.alerts.log_json:
            return
        try:
            import json
            from pathlib import Path

            out_dir = Path(self.cfg.alerts.output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)

            ts = time.strftime("%Y%m%d_%H%M%S")
            out_file = out_dir / f"alerts_{ts}.json"

            alerts = [
                {k: v for k, v in a.items() if not k.startswith("_")}
                for a in self.state.alerts
            ]
            out_file.write_text(json.dumps(alerts, indent=2,
                                            default=str))
            logger.ok(f"Alerts saved: {out_file}")
        except Exception as e:
            logger.warn(f"Could not save alerts: {e}")
