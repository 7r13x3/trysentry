"""
TrySentry — Severity scoring
Computes a 0-10 risk score from a set of alert signals.
"""

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Base weights for common signal types
SIGNAL_WEIGHTS = {
    "unsigned_binary":       0.8,
    "encoded_command":       1.2,
    "office_spawns_shell":   2.0,
    "lsass_access":          2.5,
    "remote_thread":         1.8,
    "registry_run_key":      1.2,
    "scheduled_task":        1.0,
    "service_install":       1.2,
    "wmi_persistence":       1.5,
    "unusual_port":          0.6,
    "dns_tunnel":            1.5,
    "known_malicious_ip":    2.2,
    "known_malicious_hash":  2.5,
    "yara_match":            2.0,
    "masquerading_name":     1.0,
    "suspicious_path":       0.8,
}


def score_signals(signals: list) -> float:
    """
    Combine a list of signal names into a 0–10 score.
    Caps at 10.0.
    """
    total = 0.0
    for s in signals:
        total += SIGNAL_WEIGHTS.get(s, 0.5)
    return round(min(total, 10.0), 2)


def severity_from_score(score: float) -> str:
    if score >= 8.0:
        return "critical"
    if score >= 5.5:
        return "high"
    if score >= 3.0:
        return "medium"
    return "low"


def meets_threshold(score: float, threshold: str) -> bool:
    """Is this alert severe enough to trigger `threshold`?"""
    return SEVERITY_ORDER.get(
        severity_from_score(score), 0
    ) >= SEVERITY_ORDER.get(threshold, 0)
