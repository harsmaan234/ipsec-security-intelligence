from pathlib import Path

from backend.security_engine.assessment import assess_security


PROJECT_ROOT = Path(__file__).parents[1]
RULE_PATH = PROJECT_ROOT / "rules" / "crypto_rules.yaml"


def test_detects_weak_encryption():
    evidence = {
        "selected_proposal": {
            "encryption": "3DES",
            "prf": "HMAC-SHA2-256",
            "dh_group": "MODP-2048",
        }
    }

    result = assess_security(evidence, RULE_PATH)

    assert result["finding_count"] == 1
    assert result["highest_severity"] == "high"

    finding = result["findings"][0]

    assert finding["rule_id"] == "IPSEC-CRYPTO-001"
    assert finding["provenance"] == "ASSESSED"
    assert finding["evidence"]["value"] == "3DES"


def test_detects_weak_dh():
    evidence = {
        "selected_proposal": {
            "encryption": "AES-GCM-256",
            "prf": "HMAC-SHA2-256",
            "dh_group": "MODP-1024",
        }
    }

    result = assess_security(evidence, RULE_PATH)

    assert result["finding_count"] == 1
    assert result["highest_severity"] == "high"

    assert result["findings"][0]["rule_id"] == "IPSEC-CRYPTO-003"


def test_detects_sha1():
    evidence = {
        "selected_proposal": {
            "encryption": "AES-GCM-256",
            "prf": "HMAC-SHA1",
            "dh_group": "MODP-2048",
        }
    }

    result = assess_security(evidence, RULE_PATH)

    assert result["finding_count"] == 1
    assert result["highest_severity"] == "medium"


def test_modern_configuration_has_no_findings():
    evidence = {
        "selected_proposal": {
            "encryption": "AES-GCM-256",
            "prf": "HMAC-SHA2-256",
            "dh_group": "MODP-2048",
        }
    }

    result = assess_security(evidence, RULE_PATH)

    assert result["finding_count"] == 0
    assert result["highest_severity"] == "info"
    assert result["findings"] == []


def test_unknown_configuration_produces_no_finding():
    evidence = {
        "selected_proposal": {
            "encryption": None,
            "prf": None,
            "dh_group": None,
        }
    }

    result = assess_security(evidence, RULE_PATH)

    assert result["finding_count"] == 0
    assert result["highest_severity"] == "info"
    assert result["findings"] == []
