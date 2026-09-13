from pathlib import Path
from typing import Any

import yaml


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _get_nested_value(data: dict[str, Any], path: str) -> Any:
    """Read a nested value using dot notation."""

    current: Any = data

    for part in path.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

    return current


def _evaluate_condition(
    evidence: dict[str, Any],
    condition: dict[str, Any],
) -> bool:
    """Evaluate one security-rule condition."""

    field = condition["field"]
    operator = condition["operator"]
    values = condition.get("values", [])

    observed_value = _get_nested_value(evidence, field)

    if operator == "in":
        return observed_value in values

    if operator == "equals":
        return observed_value == condition.get("value")

    return False


def load_rules(rule_path: str | Path) -> list[dict[str, Any]]:
    """Load security rules from YAML."""

    rule_path = Path(rule_path)

    if not rule_path.is_file():
        raise FileNotFoundError(f"Rule file not found: {rule_path}")

    with rule_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    return data.get("rules", [])


def assess_security(
    evidence: dict[str, Any],
    rule_path: str | Path,
) -> dict[str, Any]:
    """
    Assess security posture using deterministic evidence and rules.

    Security conclusions are ASSESSED.
    Observed protocol values remain OBSERVED.
    """

    rules = load_rules(rule_path)

    findings = []

    for rule in rules:
        condition = rule.get("condition", {})

        if not _evaluate_condition(evidence, condition):
            continue

        findings.append(
            {
                "rule_id": rule["id"],
                "name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "description": rule["description"].strip(),
                "recommendation": rule["recommendation"].strip(),
                "provenance": "ASSESSED",
                "evidence": {
                    "field": condition["field"],
                    "value": _get_nested_value(
                        evidence,
                        condition["field"],
                    ),
                },
            }
        )

    highest_severity = "info"

    for finding in findings:
        if (
            SEVERITY_ORDER[finding["severity"]]
            > SEVERITY_ORDER[highest_severity]
        ):
            highest_severity = finding["severity"]

    return {
        "finding_count": len(findings),
        "highest_severity": highest_severity,
        "findings": findings,
    }
