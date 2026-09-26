from collections import Counter

from ml.datasets.build_dataset import FEATURE_COLUMNS, build_dataset


def test_build_dataset_from_controlled_samples():
    rows, labels, metadata = build_dataset("ml/datasets/manifest.csv")

    assert len(rows) == 13
    assert len(labels) == 13
    assert len(metadata) == 13

    expected_sample_ids = [
        "icmp_001",
        "icmp_002",
        "icmp_003",
        "icmp_004",
        "icmp_005",
        "web_002",
        "web_003",
        "web_004",
        "web_005",
        "video_002",
        "video_003",
        "video_004",
        "video_005",
    ]

    assert [item["sample_id"] for item in metadata] == expected_sample_ids

    assert Counter(labels) == {
        "ICMP": 5,
        "WEB": 4,
        "VIDEO": 4,
    }

    assert [item["traffic_class"] for item in metadata] == labels

    for item in metadata:
        assert item["label_source"] == "CONTROLLED_TESTBED"
        assert item["testbed_scenario"] == "strong"

    for row in rows:
        assert set(row) == set(FEATURE_COLUMNS)

        for value in row.values():
            assert isinstance(value, float)

    icmp = rows[0]

    assert icmp["packet_count"] == 40.0
    assert icmp["total_bytes"] == 6160.0
    assert icmp["forward_packet_count"] == 20.0
    assert icmp["reverse_packet_count"] == 20.0
    assert icmp["direction_ratio"] == 0.5
    assert icmp["burst_count"] == 20.0
