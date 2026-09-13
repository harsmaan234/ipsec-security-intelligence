import csv
import io
import subprocess
from pathlib import Path


EXCHANGE_TYPES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

ENCRYPTION_ALGORITHMS = {
    20: "AES-GCM",
    12: "AES-CBC",
    13: "AES-CTR",
    23: "CAMELLIA-CBC",
    24: "CAMELLIA-CTR",
    3: "3DES",
    16: "AES-CBC",
    28: "CHACHA20-POLY1305",
}

PRF_ALGORITHMS = {
    2: "HMAC-SHA1",
    4: "HMAC-SHA2-384",
    5: "HMAC-SHA2-256",
    6: "HMAC-SHA2-512",
    7: "AES128-XCBC",
    8: "AES128-CMAC",
}

DH_GROUPS = {
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    17: "MODP-6144",
    18: "MODP-8192",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
    28: "Brainpool-224",
    29: "Brainpool-256",
    30: "Brainpool-384",
    31: "Brainpool-512",
    32: "MODP-3072-Extended",
}

def _run_tshark(pcap_path: str | Path) -> list[dict[str, str]]:
    """Extract IKE fields from a PCAP using TShark."""
    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcap_path),
            "-Y",
            "isakmp",
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=|",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "isakmp.ispi",
            "-e",
            "isakmp.rspi",
            "-e",
            "isakmp.version",
            "-e",
            "isakmp.exchangetype",
            "-e",
            "isakmp.tf.id.encr",
            "-e",
            "isakmp.tf.id.prf",
            "-e",
            "isakmp.tf.id.dh",
            "-e",
            "isakmp.tf.id.integ",
            "-e",
            "isakmp.ike2.attr.key_length",
            "-e",
            "isakmp.key_exchange.dh_group",
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    reader = csv.DictReader(
        io.StringIO(result.stdout),
        delimiter="|",
    )

    return list(reader)


def _first_int(value: str) -> int | None:
    """Return the first numeric value from a TShark field."""
    if not value:
        return None

    try:
        return int(value.split(",")[0], 0)
    except ValueError:
        return None


def _first_value(value: str) -> str | None:
    """Return the first comma-separated TShark value."""
    if not value:
        return None

    return value.split(",")[0]


def _parse_version(value: str) -> str | None:
    if value == "0x20":
        return "IKEv2"

    if value == "0x10":
        return "IKEv1"

    return value or None

def _parse_encryption(
    encryption: str | None,
    key_length: str | None,
) -> str | None:
    algorithm_id = _first_int(encryption)

    if algorithm_id is None:
        return None

    name = ENCRYPTION_ALGORITHMS.get(
        algorithm_id,
        f"UNKNOWN-{algorithm_id}",
    )

    key_bits = _first_int(key_length)

    if name == "AES-GCM" and key_bits:
        return f"AES-GCM-{key_bits}"

    if name == "AES-CBC" and key_bits:
        return f"AES-CBC-{key_bits}"

    if name == "AES-CTR" and key_bits:
        return f"AES-CTR-{key_bits}"

    return name


def extract_ike_metadata(pcap_path: str | Path) -> dict:
    """
    Extract evidence-backed IKE metadata from a PCAP.

    Only values directly observed by TShark are reported as OBSERVED.
    """
    rows = _run_tshark(pcap_path)

    ike_rows = [
        row
        for row in rows
        if row.get("isakmp.exchangetype")
    ]

    if not ike_rows:
        return {
            "observed": False,
            "protocol": "IKE",
            "version": None,
            "exchanges": [],
            "selected_proposal": None,
            "evidence": [],
        }

    exchanges = []

    for row in ike_rows:
        exchange_id = _first_int(row["isakmp.exchangetype"])

        exchanges.append(
            {
                "frame": _first_int(row["frame.number"]),
                "source": row["ip.src"] or None,
                "destination": row["ip.dst"] or None,
                "version": _parse_version(row["isakmp.version"]),
                "exchange_type": EXCHANGE_TYPES.get(
                    exchange_id,
                    f"UNKNOWN-{exchange_id}",
                ),
                "provenance": "OBSERVED",
            }
        )

    init_rows = [
        row
        for row in ike_rows
        if _first_int(row["isakmp.exchangetype"]) == 34
    ]

    selected_proposal = None

    for row in init_rows:
        encryption = _first_value(row["isakmp.tf.id.encr"])
        prf = _first_value(row["isakmp.tf.id.prf"])
        dh = _first_value(row["isakmp.tf.id.dh"])

        # In IKEv2, an IKE_SA_INIT response contains a
        # responder SPI. Initiator packets have an all-zero
        # responder SPI.
        responder_spi = row["isakmp.rspi"]

        if (
            responder_spi
            and responder_spi != "0000000000000000"
            and encryption
            and prf
            and dh
        ):
            selected_proposal = {
                "frame": _first_int(row["frame.number"]),
                "source": row["ip.src"] or None,
                "destination": row["ip.dst"] or None,
                "initiator_spi": row["isakmp.ispi"] or None,
                "responder_spi": responder_spi,
                "encryption": _parse_encryption(
                    encryption,
                    row["isakmp.ike2.attr.key_length"],
                ),
                "encryption_id": _first_int(encryption),
                "prf": PRF_ALGORITHMS.get(
                    _first_int(prf),
                    f"UNKNOWN-{_first_int(prf)}",
                ),
                "prf_id": _first_int(prf),
                "dh_group": DH_GROUPS.get(
                    _first_int(dh),
                    f"UNKNOWN-{_first_int(dh)}",
                ),
                "dh_group_id": _first_int(dh),
                "provenance": "OBSERVED",
            }

            break

    versions = {
        _parse_version(row["isakmp.version"])
        for row in ike_rows
        if row["isakmp.version"]
    }

    return {
        "observed": True,
        "protocol": "IKE",
        "version": next(iter(versions), None),
        "exchanges": exchanges,
        "selected_proposal": selected_proposal,
        "evidence": [
            {
                "type": "IKE",
                "provenance": "OBSERVED",
                "source": "TShark",
            }
        ],
    }
