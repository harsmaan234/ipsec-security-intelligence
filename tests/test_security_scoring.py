from pathlib import Path

from backend.security_engine.scoring import (
    calculate_security_score,
)


PROJECT_ROOT = Path(__file__).parents[1]
RULE_PATH = PROJECT_ROOT / "rules" / "score_rules.yaml"


def test_strong_crypto_scores_100():
    controls = [
        {
            "control_id": "CRYPTO-001",
            "name": "Cryptographic Strength",
            "status": "ASSESSED",
            "category": "cryptography",
        }
    ]

    findings = []

    result = calculate_security_score(
        controls,
        findings,
        RULE_PATH,
    )

    assert result["score"] == 100.0
    assert result["risk_level"] == "LOW"
    assert result["category_scores"]["cryptography"]["score"] == 100.0


def test_high_crypto_finding_applies_penalty():
    controls = [
        {
            "control_id": "CRYPTO-001",
            "name": "Cryptographic Strength",
            "status": "ASSESSED",
            "category": "cryptography",
        }
    ]

    findings = [
        {
            "rule_id": "IPSEC-CRYPTO-003",
            "category": "cryptography",
            "severity": "high",
            "provenance": "ASSESSED",
        }
    ]

    result = calculate_security_score(
        controls,
        findings,
        RULE_PATH,
    )

    assert result["score"] == 50.0
    assert result["risk_level"] == "HIGH"


def test_not_assessed_control_does_not_reduce_score():
    controls = [
        {
            "control_id": "CRYPTO-001",
            "name": "Cryptography",
            "status": "ASSESSED",
            "category": "cryptography",
        },
        {
            "control_id": "PFS-001",
            "name": "Perfect Forward Secrecy",
            "status": "NOT_ASSESSED",
            "category": "key_exchange",
        },
    ]

    findings = []

    result = calculate_security_score(
        controls,
        findings,
        RULE_PATH,
    )

    assert result["score"] == 100.0
    assert result["scoring_coverage"] == 30.0


def test_not_applicable_control_does_not_reduce_score():
    controls = [
        {
            "control_id": "CRYPTO-001",
            "name": "Cryptography",
            "status": "ASSESSED",
            "category": "cryptography",
        },
        {
            "control_id": "META-001",
            "name": "Metadata",
            "status": "NOT_APPLICABLE",
            "category": "metadata_exposure",
        },
    ]

    result = calculate_security_score(
        controls,
        [],
        RULE_PATH,
    )

    assert result["score"] == 100.0


def test_no_assessed_controls_returns_not_assessed():
    controls = [
        {
            "control_id": "PFS-001",
            "name": "Perfect Forward Secrecy",
            "status": "NOT_ASSESSED",
            "category": "key_exchange",
        }
    ]

    result = calculate_security_score(
        controls,
        [],
        RULE_PATH,
    )

    assert result["score"] is None
    assert result["risk_level"] == "NOT_ASSESSED"
    assert result["scoring_coverage"] == 0.0
