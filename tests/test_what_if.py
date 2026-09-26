from copy import deepcopy

from backend.fusion_engine.pipeline import analyze_pcap
from backend.security_engine.what_if import simulate_security_change


PCAP_PATH = "tests/data/ipsec_full_handshake.pcap"


def _load_evidence():
    result = analyze_pcap(PCAP_PATH)

    return {
        "ike": result["ike"],
    }


def test_what_if_detects_weak_dh_group():
    evidence = _load_evidence()

    simulation = simulate_security_change(
        evidence,
        {
            "ike.selected_proposal.dh_group": "MODP-1024",
        },
    )

    assert simulation["simulation"] is True
    assert simulation["live_changes_applied"] is False

    assert simulation["current"]["assessment"]["finding_count"] == 0
    assert simulation["projected"]["assessment"]["finding_count"] == 1

    finding = simulation["projected"]["assessment"]["findings"][0]

    assert finding["rule_id"] == "IPSEC-CRYPTO-003"
    assert finding["severity"] == "high"
    assert finding["provenance"] == "ASSESSED"

    assert simulation["current"]["score"]["score"] == 100.0
    assert simulation["projected"]["score"]["score"] == 50.0
    assert simulation["score_delta"] == -50.0


def test_what_if_does_not_modify_original_evidence():
    evidence = _load_evidence()
    original = deepcopy(evidence)

    simulate_security_change(
        evidence,
        {
            "ike.selected_proposal.dh_group": "MODP-1024",
        },
    )

    assert evidence == original
    assert (
        evidence["ike"]["selected_proposal"]["dh_group"]
        == "MODP-2048"
    )


def test_what_if_records_change():
    evidence = _load_evidence()

    simulation = simulate_security_change(
        evidence,
        {
            "ike.selected_proposal.dh_group": "MODP-1024",
        },
    )

    assert simulation["changes"] == [
        {
            "field": "ike.selected_proposal.dh_group",
            "previous_value": "MODP-2048",
            "projected_value": "MODP-1024",
        }
    ]


def test_what_if_stronger_dh_change_has_no_weak_dh_finding():
    evidence = _load_evidence()

    simulation = simulate_security_change(
        evidence,
        {
            "ike.selected_proposal.dh_group": "MODP-3072",
        },
    )

    assert simulation["projected"]["assessment"]["finding_count"] == 0
    assert simulation["projected"]["score"]["score"] == 100.0
