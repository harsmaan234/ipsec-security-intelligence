from pathlib import Path
from typing import Any

from backend.ipsec_engine.esp import extract_esp_metadata
from backend.ipsec_engine.ike import extract_ike_metadata
from backend.security_engine.assessment import assess_security
from backend.security_engine.evidence import (
    STATUS_ASSESSED,
    STATUS_NOT_ASSESSED,
    build_assessment,
    create_assessment_control,
    create_observation,
)
from backend.security_engine.scoring import calculate_security_score
from backend.security_engine.metadata_exposure import (
    assess_metadata_exposure,
)
from backend.feature_engine.traffic_features import (
    extract_traffic_features,
)

PROJECT_ROOT = Path(__file__).parents[2]

CRYPTO_RULE_PATH = (
    PROJECT_ROOT / "rules" / "crypto_rules.yaml"
)

SCORE_RULE_PATH = (
    PROJECT_ROOT / "rules" / "score_rules.yaml"
)


def _build_observations(
    ike: dict[str, Any],
    esp: dict[str, Any],
) -> list[dict[str, Any]]:
    """Convert analyzer output into normalized observations."""

    observations = []

    if ike.get("observed"):
        observations.append(
            create_observation(
                field="ike.version",
                value=ike.get("version"),
                source="TShark/IKE Analyzer",
            )
        )

        proposal = ike.get("selected_proposal")

        if proposal:
            observations.extend(
                [
                    create_observation(
                        field="ike.selected_proposal.encryption",
                        value=proposal.get("encryption"),
                        source="TShark/IKE Analyzer",
                    ),
                    create_observation(
                        field="ike.selected_proposal.prf",
                        value=proposal.get("prf"),
                        source="TShark/IKE Analyzer",
                    ),
                    create_observation(
                        field="ike.selected_proposal.dh_group",
                        value=proposal.get("dh_group"),
                        source="TShark/IKE Analyzer",
                    ),
                ]
            )

    if esp.get("observed"):
        observations.append(
            create_observation(
                field="esp.packet_count",
                value=esp.get("packet_count"),
                source="TShark/ESP Analyzer",
            )
        )

        observations.append(
            create_observation(
                field="esp.direction_count",
                value=len(esp.get("directions", [])),
                source="TShark/ESP Analyzer",
            )
        )

    return observations

METADATA_SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def _metadata_findings(
    esp: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any] | None,
]:
    """
    Assess metadata exposure across ESP flows and normalize the
    highest-severity result into the security assessment model.

    Per-flow metadata results remain available to the API layer.
    """

    feature_vectors = extract_traffic_features(esp)

    if not feature_vectors:
        return [], None

    assessments = [
        assess_metadata_exposure(feature_vector)
        for feature_vector in feature_vectors
    ]

    findings: list[dict[str, Any]] = []

    for assessment in assessments:
        for finding in assessment["findings"]:
            findings.append(
                {
                    "rule_id": (
                        "IPSEC-META-"
                        f"{finding['feature'].upper()}"
                    ),
                    "name": (
                        f"Metadata exposure: "
                        f"{finding['feature']}"
                    ),
                    "category": "metadata_exposure",
                    "severity": finding["exposure_level"].lower(),
                    "description": finding["explanation"],
                    "recommendation": finding["recommendation"],
                    "provenance": "ASSESSED",
                    "evidence": {
                        "field": finding["feature"],
                        "value": finding["observed_value"],
                    },
                }
            )

    overall = max(
        assessments,
        key=lambda assessment: (
            METADATA_SEVERITY_ORDER.get(
                assessment["overall_exposure"],
                0,
            )
        ),
    )

    return findings, overall

def _build_controls(
    ike: dict[str, Any],
    esp: dict[str, Any],
    metadata_assessment: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """
    Build assessment controls only where evidence supports assessment.

    Missing evidence becomes NOT_ASSESSED, not insecure.
    """

    controls = []

    proposal = ike.get("selected_proposal")

    if proposal:
        controls.append(
            create_assessment_control(
                control_id="IPSEC-CRYPTO-001",
                name="Cryptographic Strength",
                status=STATUS_ASSESSED,
                reason=(
                    "An IKE selected proposal was directly observed "
                    "in the PCAP."
                ),
                category="cryptography",
                evidence_refs=[
                    "ike.selected_proposal.encryption",
                    "ike.selected_proposal.prf",
                    "ike.selected_proposal.dh_group",
                ],
            )
        )

    else:
        controls.append(
            create_assessment_control(
                control_id="IPSEC-CRYPTO-001",
                name="Cryptographic Strength",
                status=STATUS_NOT_ASSESSED,
                reason=(
                    "No IKE selected proposal was directly observed "
                    "in the PCAP."
                ),
                category="cryptography",
            )
        )

    if metadata_assessment is not None:
        controls.append(
            create_assessment_control(
                control_id="IPSEC-META-001",
                name="Metadata Exposure",
                status=STATUS_ASSESSED,
                reason=(
                    "ESP traffic metadata was analyzed across "
                    "the observed bidirectional flows. Overall "
                    f"assessed exposure: "
                    f"{metadata_assessment['overall_exposure']}."
                ),
                category="metadata_exposure",
                evidence_refs=[
                    "esp.traffic_features",
                ],
            )
        )
    else:
        controls.append(
            create_assessment_control(
                control_id="IPSEC-META-001",
                name="Metadata Exposure",
                status=STATUS_NOT_ASSESSED,
                reason=(
                    "No suitable ESP flow features were available "
                    "for metadata exposure assessment."
                ),
                category="metadata_exposure",
            )
        )

    # These controls are intentionally not assessed yet.
    # We do not infer their state from packet absence or sequence
    # progression.

    controls.extend(
        [
            create_assessment_control(
                control_id="IPSEC-PFS-001",
                name="Perfect Forward Secrecy",
                status=STATUS_NOT_ASSESSED,
                reason=(
                    "The current analyzer does not have sufficient "
                    "evidence to establish PFS state."
                ),
                category="key_exchange",
            ),
            create_assessment_control(
                control_id="IPSEC-REPLAY-001",
                name="Replay Protection",
                status=STATUS_NOT_ASSESSED,
                reason=(
                    "ESP sequence numbers are observed, but replay "
                    "protection cannot be established from sequence "
                    "progression alone."
                ),
                category="sa_security",
            ),
        ]
    )

    return controls



def analyze_pcap(
    pcap_path: str | Path,
) -> dict[str, Any]:
    """
    Run the complete deterministic IPsec analysis pipeline.

    Pipeline:

        PCAP
        -> IKE + ESP extraction
        -> normalized observations
        -> security assessment
        -> security score
    """

    pcap_path = Path(pcap_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    ike = extract_ike_metadata(pcap_path)
    esp = extract_esp_metadata(pcap_path)
    metadata_findings, metadata_assessment = _metadata_findings(
        esp
    )
    observations = _build_observations(
        ike,
        esp,
    )

    controls = _build_controls(
        ike,
        esp,
        metadata_assessment,
    )

    # Security rules currently operate on IKE metadata because
    # the crypto rules target selected_proposal.* fields.
    assessment_result = assess_security(
        ike,
        CRYPTO_RULE_PATH,
    )

    assessment = build_assessment(
        observations=observations,
        controls=controls,
        findings=(
            assessment_result["findings"]
            + metadata_findings
        ),
    )

    score = calculate_security_score(
        controls=controls,
        findings=(
            assessment_result["findings"]
            + metadata_findings
        ),
    rule_path=SCORE_RULE_PATH,
    )

    return {
        "pcap": {
            "path": str(pcap_path),
        },
        "ike": ike,
        "esp": esp,
        "assessment": assessment,
        "score": score,
        "metadata_assessment": metadata_assessment,
    }
