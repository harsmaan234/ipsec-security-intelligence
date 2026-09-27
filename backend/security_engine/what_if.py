from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from backend.security_engine.crypto_profile import (
    evaluate_crypto_configuration,
)
from backend.security_engine.assessment import assess_security
from backend.security_engine.crypto_profile import (
    calculate_crypto_strength,
)
from backend.security_engine.evidence import (
    STATUS_ASSESSED,
    STATUS_NOT_ASSESSED,
    build_assessment,
    create_assessment_control,
    create_observation,
)
from backend.security_engine.scoring import calculate_security_score


PROJECT_ROOT = Path(__file__).parents[2]

CRYPTO_RULE_PATH = (
    PROJECT_ROOT / "rules" / "crypto_rules.yaml"
)

SCORE_RULE_PATH = (
    PROJECT_ROOT / "rules" / "score_rules.yaml"
)


def _get_nested_value(
    data: dict[str, Any],
    path: str,
) -> Any:
    current: Any = data

    for part in path.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

    return current


def _set_nested_value(
    data: dict[str, Any],
    path: str,
    value: Any,
) -> None:
    parts = path.split(".")
    current = data

    for part in parts[:-1]:
        child = current.get(part)

        if not isinstance(child, dict):
            child = {}
            current[part] = child

        current = child

    current[parts[-1]] = value


def _build_controls(
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    proposal = _get_nested_value(
        evidence,
        "ike.selected_proposal",
    )

    if proposal:
        crypto_control = create_assessment_control(
            control_id="IPSEC-CRYPTO-001",
            name="Cryptographic Strength",
            status=STATUS_ASSESSED,
            reason=(
                "A selected IKE proposal is available in the "
                "simulation evidence."
            ),
            category="cryptography",
            evidence_refs=[
                "ike.selected_proposal.encryption",
                "ike.selected_proposal.prf",
                "ike.selected_proposal.dh_group",
            ],
        )
    else:
        crypto_control = create_assessment_control(
            control_id="IPSEC-CRYPTO-001",
            name="Cryptographic Strength",
            status=STATUS_NOT_ASSESSED,
            reason=(
                "No selected IKE proposal is available in the "
                "simulation evidence."
            ),
            category="cryptography",
        )

    return [
        crypto_control,
        create_assessment_control(
            control_id="IPSEC-PFS-001",
            name="Perfect Forward Secrecy",
            status=STATUS_NOT_ASSESSED,
            reason=(
                "The current simulation model does not have "
                "sufficient evidence to assess PFS."
            ),
            category="key_exchange",
        ),
        create_assessment_control(
            control_id="IPSEC-REPLAY-001",
            name="Replay Protection",
            status=STATUS_NOT_ASSESSED,
            reason=(
                "The current simulation model does not establish "
                "replay protection."
            ),
            category="sa_security",
        ),
        create_assessment_control(
            control_id="IPSEC-META-001",
            name="Metadata Exposure",
            status=STATUS_NOT_ASSESSED,
            reason=(
                "Metadata exposure is outside the cryptographic "
                "what-if simulation."
            ),
            category="metadata_exposure",
        ),
    ]


def _build_observations(
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    observations = []

    proposal = _get_nested_value(
        evidence,
        "ike.selected_proposal",
    )

    if _get_nested_value(evidence, "ike.version") is not None:
        observations.append(
            create_observation(
                field="ike.version",
                value=_get_nested_value(
                    evidence,
                    "ike.version",
                ),
                source="What-If Simulation",
            )
        )

    if proposal:
        for field in (
            "encryption",
            "prf",
            "dh_group",
        ):
            value = proposal.get(field)

            if value is not None:
                observations.append(
                    create_observation(
                        field=f"ike.selected_proposal.{field}",
                        value=value,
                        source="What-If Simulation",
                    )
                )

    return observations

def _profile_findings(
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    """Convert the crypto profile evaluation into scoring findings."""

    proposal = _get_nested_value(
        evidence,
        "ike.selected_proposal",
    )

    if not proposal:
        return []

    result = evaluate_crypto_configuration(
        {
            "encryption": proposal.get("encryption"),
            "dh_group": proposal.get("dh_group"),
        }
    )

    return result.get("findings", [])

def _filter_profile_overlaps(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep YAML findings that are not replaced by crypto profiles."""

    return [
        finding
        for finding in findings
        if finding.get("evidence", {}).get("field")
        not in {
            "selected_proposal.encryption",
            "selected_proposal.dh_group",
        }
    ]

def simulate_security_change(
    current_evidence: dict[str, Any],
    changes: dict[str, Any],
) -> dict[str, Any]:
    """
    Simulate security-impacting evidence changes.

    This function:
    - does not modify a live VPN,
    - does not modify the source PCAP,
    - does not modify the original evidence object,
    - uses the existing deterministic rule and scoring engines.
    """

    if not isinstance(current_evidence, dict):
        raise TypeError("current_evidence must be a dictionary")

    if not isinstance(changes, dict):
        raise TypeError("changes must be a dictionary")

    projected_evidence = deepcopy(current_evidence)

    current_crypto_strength = calculate_crypto_strength(
        current_evidence.get("ike", {}).get("selected_proposal")
    )

    applied_changes = []

    for field, value in changes.items():
        previous_value = _get_nested_value(
            projected_evidence,
            field,
        )

        _set_nested_value(
            projected_evidence,
            field,
            value,
        )

        applied_changes.append(
            {
                "field": field,
                "previous_value": previous_value,
                "projected_value": value,
            }
        )
    projected_crypto_strength = calculate_crypto_strength(
        projected_evidence.get("ike", {}).get("selected_proposal")
    )

    current_rule_result = assess_security(
        current_evidence["ike"],
        CRYPTO_RULE_PATH,
    )

    projected_rule_result = assess_security(
        projected_evidence["ike"],
        CRYPTO_RULE_PATH,
    )

    current_rule_findings = _filter_profile_overlaps(
        current_rule_result["findings"]
    )

    projected_rule_findings = _filter_profile_overlaps(
        projected_rule_result["findings"]
    )

    current_profile_findings = _profile_findings(
        current_evidence,
    )

    projected_profile_findings = _profile_findings(
        projected_evidence,
    )

    current_findings = (
        current_rule_findings
        + current_profile_findings
    )

    projected_findings = (
        projected_rule_findings
        + projected_profile_findings
    )

    current_controls = _build_controls(
        current_evidence,
    )

    projected_controls = _build_controls(
        projected_evidence,
    )

    current_assessment = build_assessment(
        observations=_build_observations(
            current_evidence,
        ),
        controls=current_controls,
        findings=current_findings,
    )

    projected_assessment = build_assessment(
        observations=_build_observations(
            projected_evidence,
        ),
        controls=projected_controls,
        findings=projected_findings,
    )

    current_score = calculate_security_score(
        controls=current_controls,
        findings=current_findings,
        rule_path=SCORE_RULE_PATH,
    )

    projected_score = calculate_security_score(
        controls=projected_controls,
        findings=projected_findings,
        rule_path=SCORE_RULE_PATH,
    )

    current_numeric = current_score.get("score")
    projected_numeric = projected_score.get("score")

    if (
        current_numeric is not None
        and projected_numeric is not None
    ):
        score_delta = round(
            projected_numeric - current_numeric,
            2,
        )
    else:
        score_delta = None

    return {
        "simulation": True,
        "live_changes_applied": False,
        "source": "deterministic_security_rules",
        "changes": applied_changes,
        "current": {
            "crypto_strength": current_crypto_strength,
            "assessment": current_assessment,
            "score": current_score,
        },
        "projected": {
            "crypto_strength": projected_crypto_strength,
            "assessment": projected_assessment,
            "score": projected_score,
        },
        "score_delta": score_delta,
    }
