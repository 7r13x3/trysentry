"""
TrySentry — Detection pipeline
Takes an event from the bus, runs it through Sigma rules,
and triggers auto-response if severity is high enough.
"""
from .. import logger
from ..detection import sigma
from ..detection import scoring
from ..response import kill, quarantine, firewall
from .state import State


class Pipeline:
    def __init__(self, cfg, state: State):
        self.cfg = cfg
        self.state = state
        self.sigma = sigma.SigmaEngine(cfg.detection.sigma_dir)
        self.sigma.load()
        self._auto_response = cfg.response.auto_response

    # ─────────────────────────────────────────────
    def handle(self, topic: str, data: dict):
        """Called by the event bus for every event."""
        self.state.events_seen += 1

        # update process tree if it's a process event
        if topic == "process.new":
            self.state.add_process(data)
        elif topic == "process.exit":
            self.state.remove_process(data.get("pid"))

        # normalize the event for detection
        event = self._normalize(topic, data)
        if not event:
            return

        # run Sigma rules
        alerts = self.sigma.evaluate(event)
        for alert in alerts:
            self._emit(alert)

    # ─────────────────────────────────────────────
    def _normalize(self, topic: str, data: dict) -> dict:
        """Convert various event formats into a flat dict for Sigma."""
        if topic == "sysmon.event":
            return data   # already flat
        if topic == "process.new":
            return {
                "EventID": 1,
                "Image": data.get("exe", ""),
                "ProcessId": data.get("pid"),
                "ParentProcessId": data.get("ppid"),
                "ParentImage": (
                    self.state.get_process(data.get("ppid", 0)).name
                    if self.state.get_process(data.get("ppid", 0)) else ""
                ),
                "CommandLine": data.get("cmdline", ""),
                "User": data.get("user", ""),
                "_topic": topic,
            }
        if topic == "network.new":
            return {
                "EventID": 3,
                "Image": data.get("process", ""),
                "SourceIp": data.get("local", "").split(":")[0],
                "DestinationIp": data.get("remote_ip", ""),
                "DestinationPort": data.get("remote_port", 0),
                "_topic": topic,
            }
        return {}

    # ─────────────────────────────────────────────
    def _emit(self, alert: dict):
        self.state.add_alert(alert)

        sev = alert.get("severity", "low")
        if scoring.SEVERITY_ORDER.get(sev, 0) < \
           scoring.SEVERITY_ORDER.get(self.cfg.alerts.min_severity, 0):
            return

        # ── print to console ──
        if self.cfg.alerts.log_console:
            self._print_alert(alert)

        # ── auto-response ──
        if self._auto_response:
            self._auto_respond(alert)

    # ─────────────────────────────────────────────
    def _print_alert(self, alert: dict):
        mitre = alert.get("mitre", {})
        ev = alert.get("event", {})

        logger.line("─")
        logger.alert(
            f"{alert.get('severity', 'low').upper()}  "
            f"score={alert.get('score', 0)}"
        )
        logger.info(f"Rule:    {alert.get('title')}")
        if mitre.get("id"):
            logger.info(f"MITRE:   {mitre['id']} — {mitre['name']}")
        if ev.get("Image"):
            logger.info(f"Process: {ev['Image']}")
        if ev.get("ParentImage"):
            logger.info(f"Parent:  {ev['ParentImage']}")
        if ev.get("CommandLine"):
            cmd = ev["CommandLine"][:80]
            logger.info(f"Command: {cmd}")
        if ev.get("DestinationIp"):
            logger.info(f"Remote:  {ev['DestinationIp']}:"
                        f"{ev.get('DestinationPort', '')}")

    # ─────────────────────────────────────────────
    def _auto_respond(self, alert: dict):
        score = alert.get("score", 0)
        ev = alert.get("event", {})

        # kill process tree
        if scoring.meets_threshold(score, self.cfg.response.kill_threshold):
            pid = ev.get("ProcessId")
            if pid:
                result = kill.kill_tree(pid, self.cfg)
                if result.killed:
                    logger.alert(f"Response: killed PID {pid}")

        # quarantine file
        if scoring.meets_threshold(score,
                                    self.cfg.response.quarantine_threshold):
            path = ev.get("TargetFilename") or ev.get("Image")
            if path:
                q = quarantine.Quarantine(self.cfg.response.quarantine_dir)
                q.quarantine_file(path, reason=alert.get("title", ""))

        # firewall block
        if scoring.meets_threshold(score,
                                    self.cfg.response.firewall_threshold):
            ip = ev.get("DestinationIp") or ev.get("SourceIp")
            if ip:
                firewall.block_ip(ip, reason=alert.get("title", ""))
