from ml.datasets.build_dataset import FEATURE_COLUMNS, build_dataset


def test_build_dataset_from_controlled_icmp_sample():
    rows, labels, metadata = build_dataset("ml/datasets/manifest.csv")

    assert len(rows) == 1
    assert len(labels) == 1
    assert len(metadata) == 1

    assert labels[0] == "ICMP"

    assert metadata[0]["sample_id"] == "icmp_001"
    assert metadata[0]["label_source"] == "CONTROLLED_TESTBED"
    assert metadata[0]["testbed_scenario"] == "strong"

    row = rows[0]

    assert set(row) == set(FEATURE_COLUMNS)
    assert row["packet_count"] == 40.0
    assert row["total_bytes"] == 6160.0
    assert row["forward_packet_count"] == 20.0
    assert row["reverse_packet_count"] == 20.0
    assert row["direction_ratio"] == 0.5
    assert row["burst_count"] == 20.0
