from pathlib import Path
import csv

from backend.ipsec_engine.esp import extract_esp_metadata
from backend.feature_engine.traffic_features import extract_traffic_features


FEATURE_COLUMNS = [
    "packet_count",
    "total_bytes",
    "mean_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "mean_interarrival",
    "std_interarrival",
    "flow_duration",
    "packets_per_second",
    "bytes_per_second",
    "forward_packet_count",
    "reverse_packet_count",
    "forward_bytes",
    "reverse_bytes",
    "direction_ratio",
    "burst_count",
]


def load_manifest(manifest_path: str | Path) -> list[dict[str, str]]:
    path = Path(manifest_path)

    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def build_dataset(
    manifest_path: str | Path,
) -> tuple[list[dict[str, float]], list[str], list[dict[str, str]]]:
    rows = []
    labels = []
    metadata = []

    for sample in load_manifest(manifest_path):
        pcap_path = Path(sample["pcap_path"])

        if not pcap_path.exists():
            raise FileNotFoundError(
                f"PCAP not found for sample {sample['sample_id']}: {pcap_path}"
            )

        esp_metadata = extract_esp_metadata(pcap_path)
        feature_vectors = extract_traffic_features(esp_metadata)

        if len(feature_vectors) != 1:
            raise ValueError(
                f"Expected exactly one bidirectional flow for "
                f"{sample['sample_id']}, got {len(feature_vectors)}"
            )

        feature_vector = feature_vectors[0]

        row = {
            column: float(feature_vector[column])
            for column in FEATURE_COLUMNS
        }

        rows.append(row)
        labels.append(sample["traffic_class"])
        metadata.append(
            {
                "sample_id": sample["sample_id"],
                "pcap_path": sample["pcap_path"],
                "traffic_class": sample["traffic_class"],
                "label_source": sample["label_source"],
                "testbed_scenario": sample["testbed_scenario"],
            }
        )

    return rows, labels, metadata


if __name__ == "__main__":
    rows, labels, metadata = build_dataset("ml/datasets/manifest.csv")

    print(f"samples: {len(rows)}")
    print(f"labels: {labels}")

    if rows:
        print("features:")
        for name, value in rows[0].items():
            print(f"  {name}: {value}")
