from pathlib import Path

from backend.ipsec_engine.esp import extract_esp_metadata


PCAP_DIR = Path(__file__).parent / "data"


def test_extract_esp_metadata():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    result = extract_esp_metadata(pcap)

    assert result["observed"] is True
    assert result["protocol"] == "ESP"
    assert result["packet_count"] == 40


def test_detects_two_esp_directions():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    result = extract_esp_metadata(pcap)

    assert len(result["directions"]) == 2

    directions = {
        (
            direction["source"],
            direction["destination"],
            direction["spi"],
        ): direction
        for direction in result["directions"]
    }

    assert (
        "10.10.10.1",
        "10.10.10.2",
        "0xca151b76",
    ) in directions

    assert (
        "10.10.10.2",
        "10.10.10.1",
        "0xcfe67863",
    ) in directions


def test_esp_sequence_ranges():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    result = extract_esp_metadata(pcap)

    for direction in result["directions"]:
        assert direction["first_sequence"] == 1
        assert direction["last_sequence"] == 20
        assert direction["packet_count"] == 20


def test_no_esp_in_basic_traffic():
    pcap = PCAP_DIR / "basic_traffic.pcap"

    result = extract_esp_metadata(pcap)

    assert result["observed"] is False
    assert result["protocol"] == "ESP"
    assert result["packet_count"] == 0
    assert result["directions"] == []
