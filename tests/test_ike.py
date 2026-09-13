from pathlib import Path

from backend.ipsec_engine.ike import extract_ike_metadata


PCAP_DIR = Path(__file__).parent / "data"


def test_extract_ikev2_metadata():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    result = extract_ike_metadata(pcap)

    assert result["observed"] is True
    assert result["protocol"] == "IKE"
    assert result["version"] == "IKEv2"

    proposal = result["selected_proposal"]

    assert proposal is not None
    assert proposal["encryption"] == "AES-GCM-256"
    assert proposal["prf"] == "HMAC-SHA2-256"
    assert proposal["dh_group"] == "MODP-2048"
    assert proposal["provenance"] == "OBSERVED"


def test_detects_ike_exchanges():
    pcap = PCAP_DIR / "ipsec_full_handshake.pcap"

    result = extract_ike_metadata(pcap)

    exchange_types = {
        exchange["exchange_type"]
        for exchange in result["exchanges"]
    }

    assert "IKE_SA_INIT" in exchange_types
    assert "IKE_AUTH" in exchange_types
    assert "INFORMATIONAL" in exchange_types


def test_no_ike_in_plain_traffic():
    pcap = PCAP_DIR / "basic_traffic.pcap"

    result = extract_ike_metadata(pcap)

    assert result["observed"] is False
    assert result["selected_proposal"] is None
    assert result["exchanges"] == []
