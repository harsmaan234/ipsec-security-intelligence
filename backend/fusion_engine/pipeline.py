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


def _build_controls(
    ike: dict[str, Any],
    esp: dict[str, Any],
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
                    "No directly observable IKE selected proposal "
                    "was found in the PCAP."
                ),
                category="cryptography",
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
            create_assessment_control(
                control_id="IPSEC-META-001",
                name="Metadata Exposure",
                status=STATUS_NOT_ASSESSED,
                reason=(
                    "Metadata exposure analysis has not yet been "
                    "implemented."
                ),
                category="metadata_exposure",
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

    observations = _build_observations(
        ike,
        esp,
    )

    controls = _build_controls(
        ike,
        esp,
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
        findings=assessment_result["findings"],
    )

    score = calculate_security_score(
        controls=controls,
        findings=assessment_result["findings"],
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
    }
