from pathlib import Path

from backend.report_engine.pdf_report import (
    generate_executive_report,
    generate_technical_report,
)


def sample_analysis() -> dict:
    return {
        "pcap": {
            "filename": "sample-ipsec.pcap",
        },
        "ike": {
            "observed": True,
            "protocol": "IKE",
            "version": "IKEv2",
            "exchanges": [
                {
                    "exchange_type": "IKE_SA_INIT",
                    "provenance": "OBSERVED",
                }
            ],
            "selected_proposal": {
                "encryption": "AES-GCM-256",
                "prf": "HMAC-SHA2-256",
                "integrity": "N/A",
                "dh_group": "MODP-2048",
            },
        },
        "esp": {
            "observed": True,
            "protocol": "ESP",
            "packet_count": 40,
            "directions": [
                {
                    "source": "10.10.10.1",
                    "destination": "10.10.10.2",
                    "packet_count": 20,
                },
                {
                    "source": "10.10.10.2",
                    "destination": "10.10.10.1",
                    "packet_count": 20,
                },
            ],
            "sequence_analysis": {
                "note": "Sequence progression observed; replay protection status is not inferred.",
            },
        },
        "assessment": {
            "finding_count": 0,
            "coverage": {
                "assessed": 1,
                "total_applicable": 3,
                "percentage": 33.3,
            },
            "controls": [
                {
                    "control_id": "IPSEC-CRYPTO-001",
                    "name": "Cryptographic strength",
                    "category": "cryptography",
                    "status": "ASSESSED",
                    "reason": "Observed IKE selected proposal.",
                }
            ],
            "findings": [],
        },
        "score": {
            "score": 100.0,
            "risk_level": "LOW",
            "scoring_coverage": 33.3,
            "assessed_control_count": 1,
            "category_scores": {
                "cryptography": {
                    "score": 100.0,
                    "weight": 1.0,
                    "finding_count": 0,
                    "assessed_control_count": 1,
                }
            },
        },
        "traffic_intelligence": {
            "flow_count": 1,
            "flows": [
                {
                    "features": {
                        "flow_source": "10.10.10.1",
                        "flow_destination": "10.10.10.2",
                        "packet_count": 40,
                        "total_bytes": 6160,
                        "mean_packet_size": 154,
                        "std_packet_size": 0,
                        "mean_interarrival": 0.5,
                        "flow_duration": 19.4,
                        "packets_per_second": 2.06,
                        "bytes_per_second": 317,
                        "direction_ratio": 0.5,
                        "burst_count": 20,
                    },
                    "classification": {
                        "predicted_class": "ICMP",
                        "confidence": 0.975,
                        "provenance": "INFERRED",
                        "model_version": "rf-traffic-v1",
                        "explanation": {
                            "predicted_class": "ICMP",
                            "confidence": 0.975,
                            "provenance": "INFERRED",
                            "explanation_method": "SHAP_TREE_EXPLAINER",
                            "top_features": [
                                {
                                    "feature": "mean_packet_size",
                                    "value": 154,
                                    "shap_value": 0.077,
                                    "direction": "supports",
                                }
                            ],
                        },
                    },
                    "metadata_exposure": {
                        "observed": True,
                        "provenance": "ASSESSED",
                        "overall_exposure": "MEDIUM",
                        "finding_count": 1,
                        "summary": "Burst pattern may expose traffic characteristics.",
                    },
                }
            ],
        },
    }


def test_generate_executive_report():
    pdf = generate_executive_report(sample_analysis())

    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000


def test_generate_technical_report():
    pdf = generate_technical_report(sample_analysis())

    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000


def test_reports_can_be_written_to_disk(tmp_path: Path):
    analysis = sample_analysis()

    executive_path = tmp_path / "executive.pdf"
    technical_path = tmp_path / "technical.pdf"

    executive_path.write_bytes(
        generate_executive_report(analysis)
    )
    technical_path.write_bytes(
        generate_technical_report(analysis)
    )

    assert executive_path.exists()
    assert technical_path.exists()
    assert executive_path.stat().st_size > 1000
    assert technical_path.stat().st_size > 1000
