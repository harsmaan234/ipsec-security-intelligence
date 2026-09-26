from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev
from typing import Any


def _safe_mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return mean(values)


def _safe_std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return pstdev(values)


def _interarrival_times(
    timestamps: list[float],
) -> list[float]:
    if len(timestamps) < 2:
        return []

    ordered = sorted(timestamps)

    return [
        current - previous
        for previous, current in zip(
            ordered,
            ordered[1:],
        )
    ]


def _burst_count(
    interarrivals: list[float],
    threshold: float = 0.1,
) -> int:
    """
    Count simple traffic bursts.

    A new burst begins when the inter-arrival time
    exceeds the configured threshold.

    This is a descriptive traffic feature, not a
    traffic-class determination.
    """

    if not interarrivals:
        return 0

    bursts = 1

    for interval in interarrivals:
        if interval > threshold:
            bursts += 1

    return bursts


def _direction_key(
    source: str | None,
    destination: str | None,
) -> tuple[str | None, str | None]:
    return source, destination


def _canonical_flow_key(
    source: str | None,
    destination: str | None,
) -> tuple[str | None, str | None]:
    """
    Build a direction-independent flow key.

    A -> B and B -> A belong to the same
    bidirectional flow.
    """

    endpoints = [source, destination]

    endpoints.sort(
        key=lambda value: "" if value is None else value
    )

    return endpoints[0], endpoints[1]


def extract_traffic_features(
    esp_metadata: dict[str, Any],
    burst_threshold: float = 0.1,
) -> list[dict[str, Any]]:
    """
    Convert observed ESP packet metadata into
    traffic feature vectors.

    One feature vector is produced for each
    bidirectional endpoint flow.

    The features describe observable traffic behavior only.
    They do not identify or infer the application by themselves.
    """

    packets = esp_metadata.get("packets", [])

    if not packets:
        return []

    flows: dict[
        tuple[str | None, str | None],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for packet in packets:
        key = _canonical_flow_key(
            packet.get("source"),
            packet.get("destination"),
        )

        flows[key].append(packet)

    feature_vectors = []

    for (endpoint_a, endpoint_b), flow_packets in flows.items():
        valid_packets = [
            packet
            for packet in flow_packets
            if packet.get("timestamp") is not None
            and packet.get("length") is not None
        ]

        if not valid_packets:
            continue

        valid_packets.sort(
            key=lambda packet: packet["timestamp"]
        )

        timestamps = [
            float(packet["timestamp"])
            for packet in valid_packets
        ]

        lengths = [
            float(packet["length"])
            for packet in valid_packets
        ]

        interarrivals = _interarrival_times(timestamps)

        forward_packets = [
            packet
            for packet in valid_packets
            if _direction_key(
                packet.get("source"),
                packet.get("destination"),
            )
            == _direction_key(endpoint_a, endpoint_b)
        ]

        reverse_packets = [
            packet
            for packet in valid_packets
            if _direction_key(
                packet.get("source"),
                packet.get("destination"),
            )
            == _direction_key(endpoint_b, endpoint_a)
        ]

        forward_lengths = [
            float(packet["length"])
            for packet in forward_packets
        ]

        reverse_lengths = [
            float(packet["length"])
            for packet in reverse_packets
        ]

        flow_duration = (
            max(timestamps) - min(timestamps)
            if len(timestamps) >= 2
            else 0.0
        )

        packet_count = len(valid_packets)
        total_bytes = sum(lengths)

        feature_vectors.append(
            {
                "flow_source": endpoint_a,
                "flow_destination": endpoint_b,
                "packet_count": packet_count,
                "total_bytes": total_bytes,
                "mean_packet_size": round(
                    _safe_mean(lengths),
                    6,
                ),
                "std_packet_size": round(
                    _safe_std(lengths),
                    6,
                ),
                "min_packet_size": min(lengths),
                "max_packet_size": max(lengths),
                "mean_interarrival": round(
                    _safe_mean(interarrivals),
                    6,
                ),
                "std_interarrival": round(
                    _safe_std(interarrivals),
                    6,
                ),
                "flow_duration": round(
                    flow_duration,
                    6,
                ),
                "packets_per_second": round(
                    packet_count / flow_duration
                    if flow_duration > 0
                    else 0.0,
                    6,
                ),
                "bytes_per_second": round(
                    total_bytes / flow_duration
                    if flow_duration > 0
                    else 0.0,
                    6,
                ),
                "forward_packet_count": len(
                    forward_packets
                ),
                "reverse_packet_count": len(
                    reverse_packets
                ),
                "forward_bytes": sum(
                    forward_lengths
                ),
                "reverse_bytes": sum(
                    reverse_lengths
                ),
                "direction_ratio": round(
                    (
                        len(forward_packets)
                        / packet_count
                    )
                    if packet_count
                    else 0.0,
                    6,
                ),
                "burst_count": _burst_count(
                    interarrivals,
                    threshold=burst_threshold,
                ),
            }
        )

    return feature_vectors
