from backend.security_engine.crypto_profile import (
    calculate_crypto_strength,
)


def test_aes_gcm_128_with_modp_2048():
    result = calculate_crypto_strength(
        {
            "encryption": "AES-GCM-128",
            "dh_group": "MODP-2048",
        }
    )

    assert result["score"] == 78.0
    assert result["encryption_score"] == 80.0
    assert result["dh_score"] == 75.0
    assert result["level"] == "strong"


def test_aes_gcm_256_with_modp_2048():
    result = calculate_crypto_strength(
        {
            "encryption": "AES-GCM-256",
            "dh_group": "MODP-2048",
        }
    )

    assert result["score"] == 90.0
    assert result["encryption_score"] == 100.0
    assert result["dh_score"] == 75.0
    assert result["level"] == "very_strong"


def test_aes_cbc_128_with_modp_2048():
    result = calculate_crypto_strength(
        {
            "encryption": "AES-CBC-128",
            "dh_group": "MODP-2048",
        }
    )

    assert result["score"] == 66.0
    assert result["level"] == "acceptable"


def test_aes_cbc_256_with_modp_2048():
    result = calculate_crypto_strength(
        {
            "encryption": "AES-CBC-256",
            "dh_group": "MODP-2048",
        }
    )

    assert result["score"] == 84.0
    assert result["level"] == "strong"


def test_chacha20_with_modp_2048():
    result = calculate_crypto_strength(
        {
            "encryption": "CHACHA20-POLY1305",
            "dh_group": "MODP-2048",
        }
    )

    assert result["score"] == 90.0
    assert result["level"] == "very_strong"


def test_3des_with_modp_2048_is_weak():
    result = calculate_crypto_strength(
        {
            "encryption": "3DES",
            "dh_group": "MODP-2048",
        }
    )

    assert result["score"] == 42.0
    assert result["encryption_score"] == 20.0
    assert result["dh_score"] == 75.0
    assert result["level"] == "weak"


def test_aes_gcm_256_with_weak_dh():
    result = calculate_crypto_strength(
        {
            "encryption": "AES-GCM-256",
            "dh_group": "MODP-1024",
        }
    )

    assert result["score"] == 68.0
    assert result["encryption_score"] == 100.0
    assert result["dh_score"] == 20.0
    assert result["level"] == "acceptable"


def test_aes_gcm_256_with_modp_3072():
    result = calculate_crypto_strength(
        {
            "encryption": "AES-GCM-256",
            "dh_group": "MODP-3072",
        }
    )

    assert result["score"] == 96.0
    assert result["level"] == "very_strong"


def test_aes_gcm_256_with_modp_4096():
    result = calculate_crypto_strength(
        {
            "encryption": "AES-GCM-256",
            "dh_group": "MODP-4096",
        }
    )

    assert result["score"] == 100.0
    assert result["level"] == "very_strong"


def test_unknown_algorithms_are_not_treated_as_secure():
    from backend.security_engine.crypto_profile import (
        get_encryption_profile,
        get_dh_profile,
    )

    encryption = get_encryption_profile("UNKNOWN-CIPHER")
    dh = get_dh_profile("UNKNOWN-DH")

    assert encryption["known"] is False
    assert encryption["security_level"] == "unknown"

    assert dh["known"] is False
    assert dh["security_level"] == "unknown"

def test_result_is_property_derived():
    result = calculate_crypto_strength(
        {
            "encryption": "AES-GCM-256",
            "dh_group": "MODP-2048",
        }
    )

    assert result["provenance"] == "ASSESSED"
    assert result["method"] == "PROPERTY_DERIVED_CRYPTO_STRENGTH"
