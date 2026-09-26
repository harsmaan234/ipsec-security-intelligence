from __future__ import annotations

from typing import Any


SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def _exposure_item(
    *,
    feature: str,
    observed_value: Any,
    potential_inference: str,
    exposure_level: str,
    explanation: str,
    recommendation: str,
) -> dict[str, Any]:
    return {
        "feature": feature,
        "observed_value": observed_value,
        "potential_inference": potential_inference,
        "exposure_level": exposure_level,
        "explanation": explanation,
        "recommendation": recommendation,
        "provenance": "ASSESSED",
    }


def assess_metadata_exposure(
    feature_vector: dict[str, Any],
) -> dict[str, Any]:
    """
    Assess information exposure from observable encrypted-traffic
    metadata.

    This assessment does not:
    - decrypt payloads,
    - inspect plaintext,
    - identify an application deterministically,
    - replace the ML traffic classifier,
    - modify the cryptographic security score.

    It evaluates whether observable traffic characteristics may
    reveal useful information about traffic behavior.
    """

    required_features = {
        "packet_count",
        "total_bytes",
        "mean_packet_size",
        "std_packet_size",
        "flow_duration",
        "packets_per_second",
        "bytes_per_second",
        "forward_packet_count",
        "reverse_packet_count",
        "direction_ratio",
        "burst_count",
    }

    missing = sorted(
        required_features - set(feature_vector)
    )

    if missing:
        raise ValueError(
            "Feature vector is missing required fields: "
            f"{missing}"
        )

    findings: list[dict[str, Any]] = []

    packet_count = float(feature_vector["packet_count"])
    total_bytes = float(feature_vector["total_bytes"])
    mean_packet_size = float(feature_vector["mean_packet_size"])
    std_packet_size = float(feature_vector["std_packet_size"])
    flow_duration = float(feature_vector["flow_duration"])
    packets_per_second = float(
        feature_vector["packets_per_second"]
    )
    bytes_per_second = float(
        feature_vector["bytes_per_second"]
    )
    direction_ratio = float(
        feature_vector["direction_ratio"]
    )
    burst_count = float(feature_vector["burst_count"])

    if packet_count > 0 and mean_packet_size > 0:
        packet_size_variability = (
            std_packet_size / mean_packet_size
        )
    else:
        packet_size_variability = 0.0

    # Packet-size structure.
    if packet_size_variability >= 0.20:
        findings.append(
            _exposure_item(
                feature="packet_size_distribution",
                observed_value={
                    "mean_packet_size": mean_packet_size,
                    "std_packet_size": std_packet_size,
                },
                potential_inference=(
                    "Traffic characteristics and possible "
                    "application/protocol behavior"
                ),
                exposure_level="MEDIUM",
                explanation=(
                    "Variation in encrypted packet sizes can "
                    "provide observable structure that may assist "
                    "traffic classification."
                ),
                recommendation=(
                    "Consider traffic-flow confidentiality "
                    "requirements when evaluating whether "
                    "observable packet-size patterns are acceptable."
                ),
            )
        )

    # Flow volume.
    if total_bytes >= 1_000_000:
        findings.append(
            _exposure_item(
                feature="flow_volume",
                observed_value={
                    "total_bytes": total_bytes,
                    "bytes_per_second": bytes_per_second,
                },
                potential_inference=(
                    "Session scale and transfer intensity"
                ),
                exposure_level="MEDIUM",
                explanation=(
                    "Large observable flow volume can reveal "
                    "information about the scale or intensity "
                    "of a communication session even when "
                    "payload contents remain encrypted."
                ),
                recommendation=(
                    "Evaluate whether traffic-flow confidentiality "
                    "or padding controls are required for sensitive "
                    "traffic patterns."
                ),
            )
        )

    # Packet-rate exposure.
    if packets_per_second >= 20:
        findings.append(
            _exposure_item(
                feature="packet_frequency",
                observed_value={
                    "packets_per_second": packets_per_second,
                },
                potential_inference=(
                    "Activity intensity and traffic behavior"
                ),
                exposure_level="MEDIUM",
                explanation=(
                    "Observable packet frequency can reveal "
                    "communication intensity and may contribute "
                    "to traffic classification."
                ),
                recommendation=(
                    "Consider whether traffic shaping or padding "
                    "is appropriate for sensitive traffic."
                ),
            )
        )

    # Directional asymmetry.
    if direction_ratio <= 0.20 or direction_ratio >= 0.80:
        findings.append(
            _exposure_item(
                feature="direction_ratio",
                observed_value={
                    "direction_ratio": direction_ratio,
                    "forward_packet_count": float(
                        feature_vector["forward_packet_count"]
                    ),
                    "reverse_packet_count": float(
                        feature_vector["reverse_packet_count"]
                    ),
                },
                potential_inference=(
                    "Client/server traffic behavior and "
                    "communication asymmetry"
                ),
                exposure_level="MEDIUM",
                explanation=(
                    "Strong directional asymmetry is observable "
                    "without decrypting the payload and may provide "
                    "useful context for traffic characterization."
                ),
                recommendation=(
                    "Consider traffic-flow confidentiality controls "
                    "when directional patterns themselves are sensitive."
                ),
            )
        )

    # Session duration.
    if flow_duration >= 60:
        findings.append(
            _exposure_item(
                feature="flow_duration",
                observed_value={
                    "flow_duration_seconds": flow_duration,
                },
                potential_inference=(
                    "Session duration and communication behavior"
                ),
                exposure_level="LOW",
                explanation=(
                    "The duration of an encrypted flow remains "
                    "observable and can reveal communication timing "
                    "characteristics."
                ),
                recommendation=(
                    "Include session timing in metadata-exposure "
                    "reviews for sensitive communications."
                ),
            )
        )

    # Burst behavior.
    if burst_count >= 10:
        findings.append(
            _exposure_item(
                feature="burst_pattern",
                observed_value={
                    "burst_count": burst_count,
                },
                potential_inference=(
                    "Traffic activity patterns and possible "
                    "application behavior"
                ),
                exposure_level="MEDIUM",
                explanation=(
                    "Repeated traffic bursts can provide temporal "
                    "structure that may assist encrypted-traffic "
                    "classification."
                ),
                recommendation=(
                    "Evaluate whether traffic shaping or padding "
                    "is needed to reduce observable burst patterns."
                ),
            )
        )

    if not findings:
        overall_exposure = "LOW"
        summary = (
            "The analyzed flow exposes observable metadata, "
            "but no configured elevated metadata-exposure "
            "condition was triggered."
        )
    else:
        overall_exposure = max(
            (
                item["exposure_level"]
                for item in findings
            ),
            key=lambda level: SEVERITY_ORDER[level],
        )

        summary = (
            f"{len(findings)} metadata-exposure condition(s) "
            f"were identified. Overall assessed exposure level: "
            f"{overall_exposure}."
        )

    return {
        "observed": True,
        "provenance": "ASSESSED",
        "overall_exposure": overall_exposure,
        "finding_count": len(findings),
        "summary": summary,
        "findings": findings,
    }
