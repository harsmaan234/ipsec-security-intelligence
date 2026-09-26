from pathlib import Path

from backend.feature_engine.traffic_features import (
    extract_traffic_features,
)
from backend.ipsec_engine.esp import extract_esp_metadata


PCAP_DIR = Path(__file__).parent / "data"


def test_extract_traffic_features_from_real_esp_pcap():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    esp = extract_esp_metadata(pcap)

    features = extract_traffic_features(esp)

    assert len(features) == 1

    flow = features[0]

    assert flow["packet_count"] == 40
    assert flow["total_bytes"] == 40 * 154

    assert flow["forward_packet_count"] == 20
    assert flow["reverse_packet_count"] == 20

    assert flow["forward_bytes"] == 20 * 154
    assert flow["reverse_bytes"] == 20 * 154

    assert flow["flow_duration"] > 0
    assert flow["mean_packet_size"] == 154.0
    assert flow["min_packet_size"] == 154.0
    assert flow["max_packet_size"] == 154.0


def test_empty_esp_metadata_returns_no_features():
    result = extract_traffic_features(
        {
            "observed": False,
            "packets": [],
        }
    )

    assert result == []


def test_features_are_metadata_only():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    esp = extract_esp_metadata(pcap)

    features = extract_traffic_features(esp)

    flow = features[0]

    assert "payload" not in flow
    assert "plaintext" not in flow
    assert "application" not in flow
    assert "traffic_class" not in flow
