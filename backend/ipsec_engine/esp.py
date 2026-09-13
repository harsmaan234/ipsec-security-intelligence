import csv
import io
import subprocess
from pathlib import Path


def _run_tshark(pcap_path: str | Path) -> list[dict[str, str]]:
    """Extract ESP packet fields from a PCAP using TShark."""

    pcap_path = Path(pcap_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcap_path),
            "-Y",
            "esp",
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.len",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "esp.spi",
            "-e",
            "esp.sequence",
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


def _first_value(value: str) -> str | None:
    """Return the first comma-separated TShark value."""

    if not value:
        return None

    return value.split(",")[0]


def _first_int(value: str) -> int | None:
    """Return the first numeric TShark value."""

    value = _first_value(value)

    if not value:
        return None

    try:
        return int(value, 0)
    except ValueError:
        return None


def extract_esp_metadata(pcap_path: str | Path) -> dict:
    """
    Extract evidence-backed ESP metadata from a PCAP.

    Only values directly observed by TShark are reported as OBSERVED.
    """

    rows = _run_tshark(pcap_path)

    packets = []

    for row in rows:
        frame_number = _first_int(row["frame.number"])
        sequence = _first_int(row["esp.sequence"])

        if frame_number is None:
            continue

        packets.append(
            {
                "frame": frame_number,
                "timestamp": float(row["frame.time_epoch"])
                if row["frame.time_epoch"]
                else None,
                "length": int(row["frame.len"])
                if row["frame.len"]
                else None,
                "source": row["ip.src"] or None,
                "destination": row["ip.dst"] or None,
                "spi": row["esp.spi"] or None,
                "sequence": sequence,
                "provenance": "OBSERVED",
            }
        )

    if not packets:
        return {
            "observed": False,
            "protocol": "ESP",
            "packet_count": 0,
            "packets": [],
            "directions": [],
            "sequence_analysis": {
                "observed": False,
            },
            "evidence": [],
        }

    direction_map = {}

    for packet in packets:
        key = (
            packet["source"],
            packet["destination"],
            packet["spi"],
        )

        if key not in direction_map:
            direction_map[key] = {
                "source": packet["source"],
                "destination": packet["destination"],
                "spi": packet["spi"],
                "packet_count": 0,
                "first_sequence": packet["sequence"],
                "last_sequence": packet["sequence"],
                "provenance": "OBSERVED",
            }

        direction = direction_map[key]

        direction["packet_count"] += 1

        if packet["sequence"] is not None:
            if direction["first_sequence"] is None:
                direction["first_sequence"] = packet["sequence"]

            direction["last_sequence"] = packet["sequence"]

    directions = list(direction_map.values())

    return {
        "observed": True,
        "protocol": "ESP",
        "packet_count": len(packets),
        "packets": packets,
        "directions": directions,
        "sequence_analysis": {
            "observed": any(
                packet["sequence"] is not None
                for packet in packets
            ),
            "note": (
                "ESP sequence numbers are observed. "
                "Replay protection status is not inferred "
                "from sequence progression alone."
            ),
        },
        "evidence": [
            {
                "type": "ESP",
                "provenance": "OBSERVED",
                "source": "TShark",
            }
        ],
    }
