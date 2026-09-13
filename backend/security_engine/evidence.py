from typing import Any


PROVENANCE_OBSERVED = "OBSERVED"
PROVENANCE_ASSESSED = "ASSESSED"
PROVENANCE_INFERRED = "INFERRED"

STATUS_ASSESSED = "ASSESSED"
STATUS_NOT_ASSESSED = "NOT_ASSESSED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"


def create_observation(
    field: str,
    value: Any,
    source: str,
) -> dict[str, Any]:
    """
    Create an evidence item based on directly observed data.

    Observations must come from a concrete technical source such as
    TShark, Scapy, or another protocol parser.
    """

    return {
        "field": field,
        "value": value,
        "provenance": PROVENANCE_OBSERVED,
        "source": source,
    }


def create_assessment_control(
    control_id: str,
    name: str,
    status: str,
    reason: str,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    """
    Create the assessment state of a security control.

    The control status is separate from evidence provenance.
    """

    valid_statuses = {
        STATUS_ASSESSED,
        STATUS_NOT_ASSESSED,
        STATUS_NOT_APPLICABLE,
    }

    if status not in valid_statuses:
        raise ValueError(
            f"Invalid assessment status: {status}"
        )

    return {
        "control_id": control_id,
        "name": name,
        "status": status,
        "reason": reason,
        "evidence_refs": evidence_refs or [],
    }


def calculate_coverage(
    controls: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calculate assessment coverage.

    NOT_APPLICABLE controls are excluded from the denominator.

    NOT_ASSESSED is not treated as insecure.
    """

    applicable_controls = [
        control
        for control in controls
        if control["status"] != STATUS_NOT_APPLICABLE
    ]

    assessed_controls = [
        control
        for control in applicable_controls
        if control["status"] == STATUS_ASSESSED
    ]

    total = len(applicable_controls)
    assessed = len(assessed_controls)

    percentage = (
        (assessed / total) * 100
        if total
        else 100.0
    )

    return {
        "assessed": assessed,
        "total_applicable": total,
        "percentage": round(percentage, 2),
    }


def build_assessment(
    observations: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build the normalized assessment object.

    This function does not calculate a security score.
    """

    coverage = calculate_coverage(controls)

    return {
        "observations": observations,
        "controls": controls,
        "findings": findings,
        "coverage": coverage,
    }
