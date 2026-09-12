from pathlib import Path

import pytest

from backend.packet_engine.tshark import (
    TSharkError,
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
