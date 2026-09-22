"""
TrySentry — Sigma rule engine
Loads YAML rules (Sigma-style) and evaluates them against Sysmon events.
"""
import re
from pathlib import Path
from typing import List, Dict, Optional

import yaml

from .. import logger
from . import mitre
from . import scoring


class SigmaRule:
    def __init__(self, data: dict):
        self.title       = data.get("title", "Untitled")
        self.description = data.get("description", "")
        self.level       = data.get("level", "medium")
        self.mitre_id    = data.get("mitre", "")
        self.signals     = data.get("signals", [])
        self.detection   = data.get("detection", {})
        self.condition   = self.detection.get("condition", "selection")

    # ─── evaluate a single event ───
    def match(self, event: dict) -> bool:
        selections = {
            k: v for k, v in self.detection.items()
            if k != "condition"
        }
        if not selections:
            return False

        results = {}
        for name, spec in selections.items():
            results[name] = self._check_selection(spec, event)

        return self._eval_condition(self.condition, results)

    def _check_selection(self, spec: dict, event: dict) -> bool:
        """
        spec is a dict of field → expected value(s).
        Supported value forms:
          - plain string          → exact match (case-insensitive)
          - list of strings       → any match
          - "*substring*"         → contains
          - {"contains": "..."}   → contains
          - {"regex": "..."}      → regex match
        """
        for field, expected in spec.items():
            actual = str(event.get(field, "")).lower()

            if isinstance(expected, list):
                if not any(self._value_match(actual, e) for e in expected):
                    return False
            else:
                if not self._value_match(actual, expected):
                    return False
        return True

    def _value_match(self, actual: str, expected) -> bool:
        if isinstance(expected, dict):
            if "contains" in expected:
                return str(expected["contains"]).lower() in actual
            if "regex" in expected:
                try:
                    return bool(re.search(str(expected["regex"]),
                                          actual, re.IGNORECASE))
                except re.error:
                    return False
            if "startswith" in expected:
                return actual.startswith(str(expected["startswith"]).lower())
            if "endswith" in expected:
                return actual.endswith(str(expected["endswith"]).lower())
            return False

        e = str(expected).lower()
        # wildcard contains
        if e.startswith("*") and e.endswith("*"):
            return e.strip("*") in actual
        if e.endswith("*"):
            return actual.startswith(e.rstrip("*"))
        if e.startswith("*"):
            return actual.endswith(e.lstrip("*"))
        return actual == e

    def _eval_condition(self, cond: str, results: Dict[str, bool]) -> bool:
        c = cond.lower().replace(" ", "")
        # replace names with True/False
        for name, val in results.items():
            c = re.sub(rf"\b{name}\b", str(val), c)
        c = c.replace("and", " and ").replace("or", " or ")
        c = c.replace("not", " not ")
        try:
            return bool(eval(c, {"__builtins__": {}}, {}))
        except Exception:
            return False


class SigmaEngine:
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules: List[SigmaRule] = []

    def load(self):
        self.rules = []
        if not self.rules_dir.exists():
            logger.warn(f"Rules directory not found: {self.rules_dir}")
            return 0

        for path in self.rules_dir.glob("*.yaml"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict):
                    self.rules.append(SigmaRule(data))
                elif isinstance(data, list):
                    for item in data:
                        self.rules.append(SigmaRule(item))
            except Exception as e:
                logger.warn(f"Failed to load {path.name}: {e}")

        for path in self.rules_dir.glob("*.yml"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict):
                    self.rules.append(SigmaRule(data))
            except Exception:
                pass

        logger.ok(f"Sigma engine: {len(self.rules)} rules loaded")
        return len(self.rules)

    def evaluate(self, event: dict) -> List[dict]:
        """Return a list of alert dicts for matched rules."""
        alerts = []
        for rule in self.rules:
            try:
                if rule.match(event):
                    score = scoring.score_signals(rule.signals)
                    alerts.append({
                        "title":   rule.title,
                        "level":   rule.level,
                        "score":   score,
                        "severity": scoring.severity_from_score(score),
                        "mitre":   mitre.lookup(rule.mitre_id),
                        "event":   event,
                        "signals": rule.signals,
                    })
            except Exception:
                continue
        return alerts
