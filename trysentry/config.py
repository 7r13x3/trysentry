"""
TrySentry — Config loader
"""
import sys
from dataclasses import dataclass, field
from typing import List

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass
class EngineCfg:
    interval_ms: int = 1000
    correlation_window: int = 10
    max_alerts_buffer: int = 10000


@dataclass
class TelemetryCfg:
    use_sysmon: bool = True
    use_eventlog: bool = True
    use_etw: bool = False
    use_wmi: bool = True
    use_processes: bool = True
    use_network: bool = True
    use_registry: bool = True


@dataclass
class SysmonCfg:
    channel: str = "Microsoft-Windows-Sysmon/Operational"
    event_ids: List[int] = field(
        default_factory=lambda: [1, 3, 7, 8, 10, 11, 12, 13, 19, 20, 22]
    )


@dataclass
class DetectionCfg:
    sigma_dir: str = "trysentry/rules"
    yara_enabled: bool = True
    behavior_enabled: bool = True
    ioc_enabled: bool = True


@dataclass
class ResponseCfg:
    auto_response: bool = True
    kill_threshold: str = "high"
    quarantine_threshold: str = "high"
    firewall_threshold: str = "critical"
    isolation_threshold: str = "critical"
    quarantine_dir: str = "quarantine"


@dataclass
class AlertsCfg:
    output_dir: str = "logs"
    log_json: bool = True
    log_console: bool = True
    min_severity: str = "low"
    discord_webhook: str = ""


@dataclass
class DashboardCfg:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8080


@dataclass
class WhitelistCfg:
    processes: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)


@dataclass
class Config:
    engine: EngineCfg = field(default_factory=EngineCfg)
    telemetry: TelemetryCfg = field(default_factory=TelemetryCfg)
    sysmon: SysmonCfg = field(default_factory=SysmonCfg)
    detection: DetectionCfg = field(default_factory=DetectionCfg)
    response: ResponseCfg = field(default_factory=ResponseCfg)
    alerts: AlertsCfg = field(default_factory=AlertsCfg)
    dashboard: DashboardCfg = field(default_factory=DashboardCfg)
    whitelist: WhitelistCfg = field(default_factory=WhitelistCfg)


def load(path: str) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    def g(sec, key, default):
        return data.get(sec, {}).get(key, default)

    cfg = Config(
        engine=EngineCfg(
            interval_ms=int(g("engine", "interval_ms", 1000)),
            correlation_window=int(g("engine", "correlation_window", 10)),
            max_alerts_buffer=int(g("engine", "max_alerts_buffer", 10000)),
        ),
        telemetry=TelemetryCfg(
            use_sysmon=bool(g("telemetry", "use_sysmon", True)),
            use_eventlog=bool(g("telemetry", "use_eventlog", True)),
            use_etw=bool(g("telemetry", "use_etw", False)),
            use_wmi=bool(g("telemetry", "use_wmi", True)),
            use_processes=bool(g("telemetry", "use_processes", True)),
            use_network=bool(g("telemetry", "use_network", True)),
            use_registry=bool(g("telemetry", "use_registry", True)),
        ),
        sysmon=SysmonCfg(
            channel=g("sysmon", "channel",
                      "Microsoft-Windows-Sysmon/Operational"),
            event_ids=list(g("sysmon", "event_ids",
                             [1, 3, 7, 8, 10, 11, 12, 13, 19, 20, 22])),
        ),
        detection=DetectionCfg(
            sigma_dir=g("detection", "sigma_dir", "trysentry/rules"),
            yara_enabled=bool(g("detection", "yara_enabled", True)),
            behavior_enabled=bool(g("detection", "behavior_enabled", True)),
            ioc_enabled=bool(g("detection", "ioc_enabled", True)),
        ),
        response=ResponseCfg(
            auto_response=bool(g("response", "auto_response", True)),
            kill_threshold=g("response", "kill_threshold", "high"),
            quarantine_threshold=g("response", "quarantine_threshold", "high"),
            firewall_threshold=g("response", "firewall_threshold", "critical"),
            isolation_threshold=g("response", "isolation_threshold", "critical"),
            quarantine_dir=g("response", "quarantine_dir", "quarantine"),
        ),
        alerts=AlertsCfg(
            output_dir=g("alerts", "output_dir", "logs"),
            log_json=bool(g("alerts", "log_json", True)),
            log_console=bool(g("alerts", "log_console", True)),
            min_severity=g("alerts", "min_severity", "low"),
            discord_webhook=g("alerts", "discord_webhook", ""),
        ),
        dashboard=DashboardCfg(
            enabled=bool(g("dashboard", "enabled", False)),
            host=g("dashboard", "host", "127.0.0.1"),
            port=int(g("dashboard", "port", 8080)),
        ),
        whitelist=WhitelistCfg(
            processes=list(g("whitelist", "processes", [])),
            paths=list(g("whitelist", "paths", [])),
        ),
    )
    return cfg
