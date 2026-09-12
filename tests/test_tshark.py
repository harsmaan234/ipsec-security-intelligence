from pathlib import Path

import pytest

from backend.packet_engine.tshark import (
    TSharkError,
    extract_basic_packets,
    get_packet_count,
)


def test_missing_pcap_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        get_packet_count("/tmp/does-not-exist.pcap")


def test_invalid_pcap_raises_tshark_error(tmp_path: Path):
    invalid_pcap = tmp_path / "invalid.pcap"
    invalid_pcap.write_text("this is not a PCAP file")

    with pytest.raises(TSharkError):
        get_packet_count(invalid_pcap)

def test_extract_basic_packets():
    pcap_path = "tests/data/basic_traffic.pcap"

    packets = extract_basic_packets(pcap_path)

    assert len(packets) == 5

    first_packet = packets[0]

    assert first_packet["frame_number"] == 1
    assert first_packet["length"] == 40
    assert first_packet["protocol"] == "TCP"
    assert first_packet["source"] == "10.0.0.1"
    assert first_packet["destination"] == "10.0.0.2"
    assert isinstance(first_packet["timestamp"], float)
