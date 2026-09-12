from pathlib import Path
import subprocess


class TSharkError(RuntimeError):
    """Raised when TShark cannot analyze a capture file."""


def get_packet_count(pcap_path: str | Path) -> int:
    """
    Return the number of packets in a PCAP/PCAPNG capture.

    TShark performs the actual packet reading.
    """

    pcap_path = Path(pcap_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-q",
        "-z",
        "io,stat,0",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise TSharkError("Unable to execute TShark.") from exc

    if result.returncode != 0:
        error_message = result.stderr.strip() or "Unknown TShark error."
        raise TSharkError(error_message)

    for line in result.stdout.splitlines():
        stripped = line.strip()

        if not (stripped.startswith("|") and stripped.endswith("|")):
            continue

        columns = [
            column.strip()
            for column in stripped.strip("|").split("|")
        ]

        if len(columns) < 3:
            continue

        interval = columns[0]
        frames = columns[1]

        # Only process the actual interval data row.
        # Example:
        # | 0.000 <> 0.000 | 5 | 200 |
        if "<>" not in interval:
            continue

        try:
            return int(frames)
        except ValueError:
            continue

    raise TSharkError(
        "Could not determine packet count from TShark output."
    )

def extract_basic_packets(pcap_path: str | Path) -> list[dict]:
    """
    Extract basic packet metadata from a PCAP using TShark.

    Returns one dictionary per packet containing:
    - frame number
    - timestamp
    - packet length
    - protocol
    - source IP
    - destination IP
    """

    pcap_path = Path(pcap_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise TSharkError("Unable to execute TShark.") from exc

    if result.returncode != 0:
        error_message = result.stderr.strip() or "Unknown TShark error."
        raise TSharkError(error_message)

    packets = []

    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        fields = line.split("\t")

        if len(fields) != 6:
            continue

        frame_number, timestamp, length, protocol, source, destination = fields

        try:
            packet = {
                "frame_number": int(frame_number),
                "timestamp": float(timestamp),
                "length": int(length),
                "protocol": protocol or None,
                "source": source or None,
                "destination": destination or None,
            }
        except ValueError:
            continue

        packets.append(packet)

    return packets

def detect_ipsec_protocols(pcap_path: str | Path) -> dict:
    """
    Detect IPsec-related protocols present in a PCAP.

    TShark 4.2.x exposes IKE/ISAKMP using the
    'isakmp' protocol identifier.

    Returns normalized project-level protocol counts.
    """

    packets = extract_basic_packets(pcap_path)

    protocol_counts = {
        "IKE": 0,
        "ESP": 0,
        "AH": 0,
    }

    for packet in packets:
        protocol = (packet["protocol"] or "").upper()

        if "ISAKMP" in protocol:
            protocol_counts["IKE"] += 1

        if "ESP" in protocol:
            protocol_counts["ESP"] += 1

        if protocol == "AH":
            protocol_counts["AH"] += 1

    return {
        "observed": any(protocol_counts.values()),
        "protocol_counts": protocol_counts,
    }
