from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.main import app


client = TestClient(app)

PCAP_PATH = (
    Path(__file__).parent
    / "data"
    / "ipsec_full_handshake.pcap"
)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"
    assert data["service"] == "ipsec-security-intelligence"
    assert data["version"] == "0.1.0"


def test_analyze_pcap_endpoint():
    with PCAP_PATH.open("rb") as pcap_file:
        response = client.post(
            "/api/v1/analyze/pcap",
            files={
                "file": (
                    "ipsec_full_handshake.pcap",
                    pcap_file,
                    "application/vnd.tcpdump.pcap",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert "pcap" in data
    assert "ike" in data
    assert "esp" in data
    assert "assessment" in data
    assert "score" in data

    assert data["ike"]["observed"] is True
    assert data["ike"]["version"] == "IKEv2"

    assert data["esp"]["observed"] is True
    assert data["esp"]["packet_count"] > 0

    assert data["score"]["score"] is not None

def test_analyze_pcap_includes_traffic_intelligence():
    with PCAP_PATH.open("rb") as pcap_file:
        response = client.post(
            "/api/v1/analyze/pcap",
            files={
                "file": (
                    "ipsec_full_handshake.pcap",
                    pcap_file,
                    "application/vnd.tcpdump.pcap",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert "traffic_intelligence" in data

    intelligence = data["traffic_intelligence"]

    assert intelligence["flow_count"] > 0
    assert "flows" in intelligence
    assert len(intelligence["flows"]) > 0

    flow = intelligence["flows"][0]

    assert "features" in flow
    assert "classification" in flow
    assert "metadata_exposure" in flow

    classification = flow["classification"]

    assert classification["provenance"] == "INFERRED"
    assert classification["predicted_class"] in {
        "ICMP",
        "WEB",
        "VIDEO",
    }

    assert 0.0 <= classification["confidence"] <= 1.0

    metadata = flow["metadata_exposure"]

    assert metadata["provenance"] == "ASSESSED"
    assert "overall_exposure" in metadata
    assert "findings" in metadata
def test_security_simulation_endpoint():
    payload = {
        "current_evidence": {
            "ike": {
                "version": "IKEv2",
                "selected_proposal": {
                    "encryption": "AES-GCM-256",
                    "prf": "HMAC-SHA2-256",
                    "dh_group": "MODP-2048",
                },
            }
        },
        "changes": {
            "ike.selected_proposal.dh_group": "MODP-1024",
        },
    }

    response = client.post(
        "/api/v1/simulate/security",
        json=payload,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["simulation"] is True
    assert data["live_changes_applied"] is False
    assert data["source"] == "deterministic_security_rules"

    assert len(data["changes"]) == 1
    assert (
        data["changes"][0]["field"]
        == "ike.selected_proposal.dh_group"
    )
    assert (
        data["changes"][0]["previous_value"]
        == "MODP-2048"
    )
    assert (
        data["changes"][0]["projected_value"]
        == "MODP-1024"
    )

    assert data["current"]["score"]["score"] is not None
    assert data["projected"]["score"]["score"] is not None

    assert data["score_delta"] < 0

    projected_findings = (
        data["projected"]["assessment"]["findings"]
    )

    assert any(
        finding["rule_id"] == "IPSEC-CRYPTO-003"
        for finding in projected_findings
    )
