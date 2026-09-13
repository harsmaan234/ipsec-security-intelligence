from backend.security_engine.evidence import (
    PROVENANCE_OBSERVED,
    STATUS_ASSESSED,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_ASSESSED,
    build_assessment,
    calculate_coverage,
    create_assessment_control,
    create_observation,
)


def test_create_observation():
    observation = create_observation(
        field="ike.version",
        value="IKEv2",
        source="TShark",
    )

    assert observation["field"] == "ike.version"
    assert observation["value"] == "IKEv2"
    assert observation["provenance"] == PROVENANCE_OBSERVED
    assert observation["source"] == "TShark"


def test_assessed_control():
    control = create_assessment_control(
        control_id="IPSEC-PFS-001",
        name="Perfect Forward Secrecy",
        status=STATUS_ASSESSED,
        reason="PFS configuration was directly established.",
        evidence_refs=["ike.sa.001"],
    )

    assert control["control_id"] == "IPSEC-PFS-001"
    assert control["status"] == STATUS_ASSESSED
    assert control["evidence_refs"] == ["ike.sa.001"]


def test_not_assessed_is_not_insecure():
    control = create_assessment_control(
        control_id="IPSEC-PFS-001",
        name="Perfect Forward Secrecy",
        status=STATUS_NOT_ASSESSED,
        reason="The available PCAP does not provide sufficient evidence.",
    )

    assert control["status"] == STATUS_NOT_ASSESSED


def test_invalid_status_is_rejected():
    try:
        create_assessment_control(
            control_id="TEST-001",
            name="Invalid",
            status="INSECURE",
            reason="Invalid status test.",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid status was accepted")


def test_not_applicable_is_excluded_from_coverage():
    controls = [
        create_assessment_control(
            "CTRL-001",
            "Control One",
            STATUS_ASSESSED,
            "Evidence available.",
        ),
        create_assessment_control(
            "CTRL-002",
            "Control Two",
            STATUS_NOT_ASSESSED,
            "Evidence unavailable.",
        ),
        create_assessment_control(
            "CTRL-003",
            "Control Three",
            STATUS_NOT_APPLICABLE,
            "Not applicable to this VPN.",
        ),
    ]

    result = calculate_coverage(controls)

    assert result["assessed"] == 1
    assert result["total_applicable"] == 2
    assert result["percentage"] == 50.0


def test_full_assessment_structure():
    observations = [
        create_observation(
            field="ike.version",
            value="IKEv2",
            source="TShark",
        )
    ]

    controls = [
        create_assessment_control(
            "IPSEC-CRYPTO-001",
            "Cryptographic Strength",
            STATUS_ASSESSED,
            "Observed configuration was evaluated.",
        ),
        create_assessment_control(
            "IPSEC-PFS-001",
            "Perfect Forward Secrecy",
            STATUS_NOT_ASSESSED,
            "Insufficient PCAP evidence.",
        ),
    ]

    findings = [
        {
            "rule_id": "IPSEC-CRYPTO-001",
            "severity": "high",
            "provenance": "ASSESSED",
        }
    ]

    result = build_assessment(
        observations=observations,
        controls=controls,
        findings=findings,
    )

    assert len(result["observations"]) == 1
    assert len(result["controls"]) == 2
    assert len(result["findings"]) == 1
    assert result["coverage"]["assessed"] == 1
    assert result["coverage"]["total_applicable"] == 2
    assert result["coverage"]["percentage"] == 50.0

