from __future__ import annotations

from typing import Any


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


ENCRYPTION_PROFILES: dict[str, dict[str, Any]] = {
    "AES-GCM-128": {
        "family": "AES",
        "key_size_bits": 128,
        "mode": "GCM",
        "aead": True,
        "legacy": False,
        "security_level": "strong",
        "description": (
            "AES with a 128-bit key in GCM authenticated-encryption mode."
        ),
    },
    "AES-GCM-256": {
        "family": "AES",
        "key_size_bits": 256,
        "mode": "GCM",
        "aead": True,
        "legacy": False,
        "security_level": "very_strong",
        "description": (
            "AES with a 256-bit key in GCM authenticated-encryption mode."
        ),
    },
    "AES-CBC-128": {
        "family": "AES",
        "key_size_bits": 128,
        "mode": "CBC",
        "aead": False,
        "legacy": False,
        "security_level": "acceptable",
        "description": (
            "AES with a 128-bit key in CBC mode; integrity "
            "requires a separate integrity mechanism."
        ),
    },
    "AES-CBC-256": {
        "family": "AES",
        "key_size_bits": 256,
        "mode": "CBC",
        "aead": False,
        "legacy": False,
        "security_level": "strong",
        "description": (
            "AES with a 256-bit key in CBC mode; integrity "
            "requires a separate integrity mechanism."
        ),
    },
    "AES-CBC": {
        "family": "AES",
        "key_size_bits": None,
        "mode": "CBC",
        "aead": False,
        "legacy": False,
        "security_level": "acceptable",
        "description": (
            "AES in CBC mode; the observed evidence does not "
            "identify the key size."
        ),
    },
    "AES-CTR": {
        "family": "AES",
        "key_size_bits": None,
        "mode": "CTR",
        "aead": False,
        "legacy": False,
        "security_level": "acceptable",
        "description": (
            "AES in counter mode; the observed evidence does not "
            "identify the key size."
        ),
    },
    "CHACHA20-POLY1305": {
        "family": "ChaCha20",
        "key_size_bits": 256,
        "mode": "POLY1305",
        "aead": True,
        "legacy": False,
        "security_level": "very_strong",
        "description": (
            "ChaCha20-Poly1305 authenticated-encryption construction "
            "with a 256-bit key."
        ),
    },
    "3DES": {
        "family": "Triple-DES",
        "key_size_bits": 112,
        "mode": "3DES",
        "aead": False,
        "legacy": True,
        "security_level": "weak",
        "description": (
            "Triple-DES is a legacy block cipher and should not be "
            "used for new modern IPsec deployments."
        ),
    },
    "DES": {
        "family": "DES",
        "key_size_bits": 56,
        "mode": "DES",
        "aead": False,
        "legacy": True,
        "security_level": "weak",
        "description": (
            "DES has a 56-bit effective key size and is considered "
            "cryptographically weak."
        ),
    },
}


DH_PROFILES: dict[str, dict[str, Any]] = {
    "MODP-1024": {
        "family": "MODP",
        "size_bits": 1024,
        "security_level": "weak",
        "legacy": True,
        "description": (
            "1024-bit MODP Diffie-Hellman group with insufficient "
            "strength for modern deployments."
        ),
    },
    "MODP-2048": {
        "family": "MODP",
        "size_bits": 2048,
        "security_level": "acceptable",
        "legacy": False,
        "description": (
            "2048-bit MODP Diffie-Hellman group."
        ),
    },
    "MODP-3072": {
        "family": "MODP",
        "size_bits": 3072,
        "security_level": "strong",
        "legacy": False,
        "description": (
            "3072-bit MODP Diffie-Hellman group."
        ),
    },
    "MODP-4096": {
        "family": "MODP",
        "size_bits": 4096,
        "security_level": "very_strong",
        "legacy": False,
        "description": (
            "4096-bit MODP Diffie-Hellman group."
        ),
    },
    "ECP-256": {
        "family": "ECP",
        "size_bits": 256,
        "security_level": "strong",
        "legacy": False,
        "description": (
            "256-bit elliptic-curve Diffie-Hellman group."
        ),
    },
    "ECP-384": {
        "family": "ECP",
        "size_bits": 384,
        "security_level": "very_strong",
        "legacy": False,
        "description": (
            "384-bit elliptic-curve Diffie-Hellman group."
        ),
    },
    "ECP-521": {
        "family": "ECP",
        "size_bits": 521,
        "security_level": "very_strong",
        "legacy": False,
        "description": (
            "521-bit elliptic-curve Diffie-Hellman group."
        ),
    },
}


def get_encryption_profile(
    algorithm: str | None,
) -> dict[str, Any]:
    """
    Return deterministic properties for an encryption algorithm.

    Unknown algorithms are represented explicitly rather than
    being treated as secure or insecure.
    """

    if algorithm is None:
        return {
            "algorithm": None,
            "known": False,
            "security_level": "unknown",
            "reason": "No encryption algorithm was observed.",
        }

    profile = ENCRYPTION_PROFILES.get(algorithm)

    if profile is None:
        return {
            "algorithm": algorithm,
            "known": False,
            "security_level": "unknown",
            "reason": (
                "The algorithm is not present in the local "
                "cryptographic profile catalog."
            ),
        }

    return {
        "algorithm": algorithm,
        "known": True,
        **profile,
    }


def get_dh_profile(
    dh_group: str | None,
) -> dict[str, Any]:
    """
    Return deterministic properties for a DH group.

    Unknown groups are represented explicitly rather than
    being treated as secure or insecure.
    """

    if dh_group is None:
        return {
            "group": None,
            "known": False,
            "security_level": "unknown",
            "reason": "No DH group was observed.",
        }

    profile = DH_PROFILES.get(dh_group)

    if profile is None:
        return {
            "group": dh_group,
            "known": False,
            "security_level": "unknown",
            "reason": (
                "The DH group is not present in the local "
                "cryptographic profile catalog."
            ),
        }

    return {
        "group": dh_group,
        "known": True,
        **profile,
    }


def evaluate_crypto_configuration(
    proposal: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Evaluate encryption and DH properties from an IKE proposal.

    This evaluator produces deterministic cryptographic metadata
    and findings. It does not calculate the overall security score.
    """

    if not proposal:
        return {
            "observed": False,
            "provenance": "ASSESSED",
            "encryption": get_encryption_profile(None),
            "dh": get_dh_profile(None),
            "findings": [],
        }

    encryption = get_encryption_profile(
        proposal.get("encryption")
    )

    dh = get_dh_profile(
        proposal.get("dh_group")
    )

    findings: list[dict[str, Any]] = []

    if encryption.get("security_level") == "weak":
        findings.append(
            {
                "rule_id": "IPSEC-CRYPTO-001",
                "name": "Weak encryption profile",
                "category": "cryptography",
                "severity": "high",
                "description": (
                    f"{encryption['algorithm']} is classified as "
                    "weak or legacy by the local cryptographic "
                    "policy profile."
                ),
                "recommendation": (
                    "Use a modern authenticated-encryption "
                    "algorithm such as AES-GCM or "
                    "CHACHA20-POLY1305."
                ),
                "provenance": "ASSESSED",
                "evidence": {
                    "field": "selected_proposal.encryption",
                    "value": encryption["algorithm"],
                },
            }
        )

    if dh.get("security_level") == "weak":
        findings.append(
            {
                "rule_id": "IPSEC-CRYPTO-003",
                "name": "Weak Diffie-Hellman profile",
                "category": "cryptography",
                "severity": "high",
                "description": (
                    f"{dh['group']} is classified as weak or legacy "
                    "by the local cryptographic policy profile."
                ),
                "recommendation": (
                    "Use a stronger approved Diffie-Hellman "
                    "or elliptic-curve group."
                ),
                "provenance": "ASSESSED",
                "evidence": {
                    "field": "selected_proposal.dh_group",
                    "value": dh["group"],
                },
            }
        )

    highest_severity = "info"

    for finding in findings:
        if (
            SEVERITY_ORDER[finding["severity"]]
            > SEVERITY_ORDER[highest_severity]
        ):
            highest_severity = finding["severity"]

    return {
        "observed": True,
        "provenance": "ASSESSED",
        "encryption": encryption,
        "dh": dh,
        "findings": findings,
        "finding_count": len(findings),
        "highest_severity": highest_severity,
    }

def calculate_crypto_strength(
    proposal: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Derive cryptographic strength from cryptographic properties.

    This is a transparent local policy model. It does not assign
    arbitrary scores to individual algorithm names.
    """

    if not proposal:
        return {
            "available": False,
            "score": None,
            "level": "unknown",
            "encryption_score": None,
            "dh_score": None,
            "reason": "No cryptographic proposal was observed.",
            "provenance": "ASSESSED",
            "method": "PROPERTY_DERIVED_CRYPTO_STRENGTH",
        }

    encryption = get_encryption_profile(
        proposal.get("encryption")
    )

    dh = get_dh_profile(
        proposal.get("dh_group")
    )

    # ---------------------------------------------------------
    # Encryption strength
    # ---------------------------------------------------------

    if not encryption.get("known"):
        encryption_score = 40.0

    elif encryption.get("legacy"):
        encryption_score = 20.0

    else:
        key_size = encryption.get("key_size_bits")

        if key_size is None:
            encryption_score = 70.0
        else:
            # Treat 128-bit AES-class key strength as the
            # modern baseline rather than 50% of the score.
            #
            # 128 bits -> 70
            # 256 bits -> 100
            baseline_bits = 128.0
            maximum_bits = 256.0

            normalized = (
                (key_size - baseline_bits)
                / (maximum_bits - baseline_bits)
            )

            normalized = max(
                0.0,
                min(1.0, normalized),
            )

            encryption_score = (
                70.0
                + (30.0 * normalized)
            )

        # AEAD provides integrated confidentiality and integrity.
        if encryption.get("aead"):
            encryption_score += 10.0

        # CBC/CTR require separate integrity protection and
        # therefore receive a property-based reduction.
        if encryption.get("mode") in {"CBC", "CTR"}:
            encryption_score -= 10.0

    encryption_score = max(
        0.0,
        min(100.0, encryption_score),
    )

    # ---------------------------------------------------------
    # DH strength
    # ---------------------------------------------------------

    if not dh.get("known"):
        dh_score = 40.0

    elif dh.get("legacy"):
        dh_score = 20.0

    elif dh.get("family") == "MODP":
        size_bits = dh.get("size_bits", 0)

        if size_bits < 2048:
            dh_score = 20.0
        elif size_bits < 3072:
            dh_score = 75.0
        elif size_bits < 4096:
            dh_score = 90.0
        else:
            dh_score = 100.0

    elif dh.get("family") == "ECP":
        size_bits = dh.get("size_bits", 0)

        if size_bits < 256:
            dh_score = 50.0
        elif size_bits == 256:
            dh_score = 85.0
        elif size_bits <= 384:
            dh_score = 95.0
        else:
            dh_score = 100.0

    else:
        dh_score = 40.0

    dh_score = max(
        0.0,
        min(100.0, dh_score),
    )

    # ---------------------------------------------------------
    # Combined cryptographic strength
    # ---------------------------------------------------------

    combined_score = round(
        (encryption_score * 0.60)
        + (dh_score * 0.40),
        2,
    )

    if combined_score >= 90:
        level = "very_strong"
    elif combined_score >= 75:
        level = "strong"
    elif combined_score >= 50:
        level = "acceptable"
    elif combined_score >= 25:
        level = "weak"
    else:
        level = "very_weak"

    return {
        "available": True,
        "score": combined_score,
        "level": level,
        "encryption_score": round(
            encryption_score,
            2,
        ),
        "dh_score": round(
            dh_score,
            2,
        ),
        "provenance": "ASSESSED",
        "method": "PROPERTY_DERIVED_CRYPTO_STRENGTH",
    }
