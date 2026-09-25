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

    assert result["assessment"]["coverage"]["assessed"] == 1

    assert result["assessment"]["findings"] == []

    assert result["score"]["score"] == 100.0
    assert result["score"]["risk_level"] == "LOW"

    assert result["score"]["scoring_coverage"] == 30.0


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
        == "NOT_ASSESSED"
    )


def test_pipeline_handles_plain_traffic():
    pcap = PCAP_DIR / "basic_traffic.pcap"

    result = analyze_pcap(pcap)

    assert result["ike"]["observed"] is False
    assert result["esp"]["observed"] is False

    assert result["assessment"]["finding_count"] == 0

    assert result["score"]["score"] is None
    assert result["score"]["risk_level"] == "NOT_ASSESSED"

