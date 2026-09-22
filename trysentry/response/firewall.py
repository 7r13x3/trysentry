"""
TrySentry — Firewall blocking
Adds Windows Firewall rules to block inbound + outbound traffic to an IP.
Uses netsh advfirewall. Requires Administrator.
"""
import subprocess
from .. import logger


RULE_PREFIX = "TrySentry_Block_"


def _run(cmd: list) -> tuple:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)


def block_ip(ip: str, reason: str = "") -> bool:
    """
    Block all traffic to/from an IP address.
    Creates one inbound rule and one outbound rule.
    """
    if not ip or ip in ("0.0.0.0", "127.0.0.1", "::1"):
        logger.warn(f"Refusing to block reserved IP: {ip}")
        return False

    name_out = f"{RULE_PREFIX}out_{ip}"
    name_in = f"{RULE_PREFIX}in_{ip}"

    # outbound
    code, _, err = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name_out}",
        "dir=out",
        "action=block",
        f"remoteip={ip}",
    ])
    if code != 0:
        logger.warn(f"Failed to add outbound rule: {err.strip()}")
        return False

    # inbound
    code, _, err = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name_in}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
    ])
    if code != 0:
        logger.warn(f"Failed to add inbound rule: {err.strip()}")
        return False

    logger.alert(f"Firewall: blocked {ip}  ({reason})")
    return True


def unblock_ip(ip: str) -> bool:
    """Remove the firewall rules for an IP."""
    name_out = f"{RULE_PREFIX}out_{ip}"
    name_in = f"{RULE_PREFIX}in_{ip}"

    code1, _, _ = _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={name_out}",
    ])
    code2, _, _ = _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={name_in}",
    ])

    if code1 == 0 or code2 == 0:
        logger.ok(f"Firewall: unblocked {ip}")
        return True
    return False


def list_blocked() -> list:
    """List all IPs blocked by TrySentry."""
    code, out, _ = _run([
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name=all",
    ])
    blocked = set()
    for line in out.splitlines():
        if RULE_PREFIX in line:
            # extract IP from rule name
            parts = line.split(RULE_PREFIX)
            if len(parts) > 1:
                after = parts[1]
                # rule name format: out_1.2.3.4 or in_1.2.3.4
                for pref in ("out_", "in_"):
                    if after.startswith(pref):
                        ip = after[len(pref):].strip().split()[0]
                        blocked.add(ip)
    return sorted(blocked)
