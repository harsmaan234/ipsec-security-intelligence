from ml.datasets.build_dataset import FEATURE_COLUMNS, build_dataset


def test_build_dataset_from_controlled_samples():
    rows, labels, metadata = build_dataset("ml/datasets/manifest.csv")

    assert len(rows) == 3
    assert len(labels) == 3
    assert len(metadata) == 3

    assert labels == ["ICMP", "WEB", "VIDEO"]

    assert metadata[0]["sample_id"] == "icmp_001"
    assert metadata[0]["label_source"] == "CONTROLLED_TESTBED"
    assert metadata[0]["testbed_scenario"] == "strong"

    assert metadata[1]["sample_id"] == "web_001"
    assert metadata[1]["label_source"] == "CONTROLLED_TESTBED"
    assert metadata[1]["testbed_scenario"] == "strong"

    assert metadata[2]["sample_id"] == "video_001"
    assert metadata[2]["label_source"] == "CONTROLLED_TESTBED"
    assert metadata[2]["testbed_scenario"] == "strong"

    for row in rows:
        assert set(row) == set(FEATURE_COLUMNS)

    icmp = rows[0]

    assert icmp["packet_count"] == 40.0
    assert icmp["total_bytes"] == 6160.0
    assert icmp["forward_packet_count"] == 20.0
    assert icmp["reverse_packet_count"] == 20.0
    assert icmp["direction_ratio"] == 0.5
    assert icmp["burst_count"] == 20.0

    web = rows[1]

    assert web["packet_count"] == 259.0
    assert web["total_bytes"] == 51038.0
    assert web["forward_packet_count"] == 139.0
    assert web["reverse_packet_count"] == 120.0
    assert web["direction_ratio"] == 0.53668
    assert web["burst_count"] == 20.0

    video = rows[2]

    assert video["packet_count"] == 23106.0
    assert video["total_bytes"] == 23760044.0
    assert video["forward_packet_count"] == 7742.0
    assert video["reverse_packet_count"] == 15364.0
    assert video["direction_ratio"] == 0.335064
    assert video["max_packet_size"] == 1514.0
    assert video["burst_count"] == 1.0
