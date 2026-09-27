from pathlib import Path

from backend.fusion_engine.pipeline import analyze_pcap


PCAP_DIR = Path(__file__).parent / "data"


def test_full_ipsec_pipeline():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    result = analyze_pcap(pcap)

    assert result["ike"]["observed"] is True
    assert result["ike"]["version"] == "IKEv2"

    assert result["ike"]["selected_proposal"] is not None

    proposal = result["ike"]["selected_proposal"]

    assert proposal["encryption"] == "AES-GCM-256"
    assert proposal["prf"] == "HMAC-SHA2-256"
    assert proposal["dh_group"] == "MODP-2048"

    assert result["esp"]["observed"] is True
    assert result["esp"]["packet_count"] == 40

    assert result["assessment"]["coverage"]["assessed"] == 2
    assert result["assessment"]["coverage"]["total_applicable"] == 4
    assert result["assessment"]["coverage"]["percentage"] == 50.0

    controls = {
        control["control_id"]: control
        for control in result["assessment"]["controls"]
    }

    assert controls["IPSEC-CRYPTO-001"]["status"] == "ASSESSED"
    assert controls["IPSEC-META-001"]["status"] == "ASSESSED"
    assert controls["IPSEC-PFS-001"]["status"] == "NOT_ASSESSED"
    assert controls["IPSEC-REPLAY-001"]["status"] == "NOT_ASSESSED"

    assert result["metadata_assessment"]["observed"] is True
    assert result["metadata_assessment"]["provenance"] == "ASSESSED"
    assert result["metadata_assessment"]["overall_exposure"] == "MEDIUM"
    assert result["metadata_assessment"]["finding_count"] == 1

    metadata_findings = [
        finding
        for finding in result["assessment"]["findings"]
        if finding["category"] == "metadata_exposure"
    ]

    assert len(metadata_findings) == 1
    assert metadata_findings[0]["rule_id"] == "IPSEC-META-BURST_PATTERN"
    assert metadata_findings[0]["severity"] == "medium"
    assert metadata_findings[0]["provenance"] == "ASSESSED"

    assert result["score"]["score"] == 91.67
    assert result["score"]["risk_level"] == "LOW"
    assert result["score"]["scoring_coverage"] == 45.0

    assert result["score"]["risk_level"] == "LOW"


def test_pipeline_preserves_not_assessed_controls():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    result = analyze_pcap(pcap)

    controls = result["assessment"]["controls"]

    controls_by_id = {
        control["control_id"]: control
        for control in controls
    }

    assert (
        controls_by_id["IPSEC-PFS-001"]["status"]
        == "NOT_ASSESSED"
    )

    assert (
        controls_by_id["IPSEC-REPLAY-001"]["status"]
        == "NOT_ASSESSED"
    )

    assert (
        controls_by_id["IPSEC-META-001"]["status"]
        == "ASSESSED"
    )


def test_pipeline_handles_plain_traffic():
    pcap = PCAP_DIR / "basic_traffic.pcap"

    result = analyze_pcap(pcap)

    assert result["ike"]["observed"] is False
    assert result["esp"]["observed"] is False

    assert result["assessment"]["finding_count"] == 0

    assert result["score"]["score"] is None
    assert result["score"]["risk_level"] == "NOT_ASSESSED"

