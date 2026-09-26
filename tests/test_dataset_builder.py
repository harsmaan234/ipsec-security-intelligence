from ml.datasets.build_dataset import FEATURE_COLUMNS, build_dataset


def test_build_dataset_from_controlled_samples():
    rows, labels, metadata = build_dataset("ml/datasets/manifest.csv")

    assert len(rows) == 2
    assert len(labels) == 2
    assert len(metadata) == 2

    assert labels == ["ICMP", "WEB"]

    assert metadata[0]["sample_id"] == "icmp_001"
    assert metadata[0]["label_source"] == "CONTROLLED_TESTBED"
    assert metadata[0]["testbed_scenario"] == "strong"

    assert metadata[1]["sample_id"] == "web_001"
    assert metadata[1]["label_source"] == "CONTROLLED_TESTBED"
    assert metadata[1]["testbed_scenario"] == "strong"

    icmp = rows[0]

    assert set(icmp) == set(FEATURE_COLUMNS)
    assert icmp["packet_count"] == 40.0
    assert icmp["total_bytes"] == 6160.0
    assert icmp["forward_packet_count"] == 20.0
    assert icmp["reverse_packet_count"] == 20.0
    assert icmp["direction_ratio"] == 0.5
    assert icmp["burst_count"] == 20.0

    web = rows[1]

    assert set(web) == set(FEATURE_COLUMNS)
    assert web["packet_count"] == 259.0
    assert web["total_bytes"] == 51038.0
    assert web["forward_packet_count"] == 139.0
    assert web["reverse_packet_count"] == 120.0
    assert web["direction_ratio"] == 0.53668
    assert web["burst_count"] == 20.0

    assert web["packet_count"] > icmp["packet_count"]
    assert web["total_bytes"] > icmp["total_bytes"]
    assert web["packets_per_second"] > icmp["packets_per_second"]
    assert web["std_packet_size"] > icmp["std_packet_size"]
