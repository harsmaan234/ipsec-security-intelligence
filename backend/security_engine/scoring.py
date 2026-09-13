from pathlib import Path
from typing import Any

import yaml


def load_score_rules(
    rule_path: str | Path,
) -> dict[str, Any]:
    """Load scoring policy from YAML."""

    rule_path = Path(rule_path)

    if not rule_path.is_file():
        raise FileNotFoundError(
            f"Score rule file not found: {rule_path}"
        )

    with rule_path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def _severity_penalty(
    severity: str,
    penalties: dict[str, int],
) -> int:
    """Return the configured penalty for a finding severity."""

    return penalties.get(severity.lower(), 0)


def _category_score(
    findings: list[dict[str, Any]],
    penalties: dict[str, int],
) -> float:
    """
    Calculate a category score.

    Multiple findings may contribute penalties, but the score
    cannot fall below zero.
    """

    total_penalty = sum(
        _severity_penalty(
            finding.get("severity", "info"),
            penalties,
        )
        for finding in findings
    )

    return max(0.0, 100.0 - total_penalty)


def _risk_level(
    score: float,
    risk_levels: list[dict[str, Any]],
) -> str:
    """Map a numerical score to a configured risk level."""

    for level in risk_levels:
        if (
            level["minimum"]
            <= score
            <= level["maximum"]
        ):
            return level["level"]

    return "UNKNOWN"


def calculate_security_score(
    controls: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    rule_path: str | Path,
) -> dict[str, Any]:
    """
    Calculate a transparent 0–100 security score.

    NOT_ASSESSED and NOT_APPLICABLE controls do not contribute
    to the score.
    """

    rules = load_score_rules(rule_path)

    categories = rules.get("categories", {})
    penalties = rules.get("severity_penalties", {})
    risk_levels = rules.get("risk_levels", [])

    assessed_categories = {}

    for category in categories:
        category_controls = [
            control
            for control in controls
            if control.get("category") == category
            and control.get("status") == "ASSESSED"
        ]

        if not category_controls:
            continue

        category_findings = [
            finding
            for finding in findings
            if finding.get("category") == category
        ]

        score = _category_score(
            category_findings,
            penalties,
        )

        assessed_categories[category] = {
            "score": round(score, 2),
            "weight": categories[category]["weight"],
            "finding_count": len(category_findings),
            "assessed_control_count": len(category_controls),
        }

    total_weight = sum(
        category["weight"]
        for category in assessed_categories.values()
    )

    if total_weight == 0:
        return {
            "score": None,
            "risk_level": "NOT_ASSESSED",
            "category_scores": {},
            "scoring_coverage": 0.0,
        }

    weighted_score = sum(
        category["score"] * category["weight"]
        for category in assessed_categories.values()
    ) / total_weight

    score = round(weighted_score, 2)

    assessed_control_count = sum(
        category["assessed_control_count"]
        for category in assessed_categories.values()
    )

    return {
        "score": score,
        "risk_level": _risk_level(
            score,
            risk_levels,
        ),
        "category_scores": assessed_categories,
        "scoring_coverage": round(
            (
                total_weight
                / sum(
                    category["weight"]
                    for category in categories.values()
                )
            )
            * 100,
            2,
        ),
        "assessed_control_count": assessed_control_count,
    }
