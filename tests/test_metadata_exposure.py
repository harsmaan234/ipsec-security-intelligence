from backend.security_engine.metadata_exposure import (
    assess_metadata_exposure,
)


def make_feature_vector(**overrides):
    features = {
        "packet_count": 100.0,
        "total_bytes": 50_000.0,
        "mean_packet_size": 500.0,
        "std_packet_size": 20.0,
        "min_packet_size": 480.0,
        "max_packet_size": 520.0,
        "mean_interarrival": 0.5,
        "std_interarrival": 0.1,
        "flow_duration": 20.0,
        "packets_per_second": 5.0,
        "bytes_per_second": 2500.0,
        "forward_packet_count": 50.0,
        "reverse_packet_count": 50.0,
        "forward_bytes": 25_000.0,
        "reverse_bytes": 25_000.0,
        "direction_ratio": 0.5,
        "burst_count": 2.0,
    }

    features.update(overrides)

    return features


def test_metadata_exposure_returns_assessment_schema():
    result = assess_metadata_exposure(
        make_feature_vector()
    )

    assert result["observed"] is True
    assert result["provenance"] == "ASSESSED"
    assert result["overall_exposure"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
    }

    assert isinstance(result["finding_count"], int)
    assert isinstance(result["findings"], list)


def test_high_volume_flow_creates_volume_finding():
    result = assess_metadata_exposure(
        make_feature_vector(
            total_bytes=2_000_000.0,
            bytes_per_second=100_000.0,
        )
    )

    features = {
        finding["feature"]
        for finding in result["findings"]
    }

    assert "flow_volume" in features


def test_high_packet_rate_creates_frequency_finding():
    result = assess_metadata_exposure(
        make_feature_vector(
            packets_per_second=50.0,
        )
    )

    features = {
        finding["feature"]
        for finding in result["findings"]
    }

    assert "packet_frequency" in features


def test_directional_asymmetry_creates_finding():
    result = assess_metadata_exposure(
        make_feature_vector(
            direction_ratio=0.90,
        )
    )

    features = {
        finding["feature"]
        for finding in result["findings"]
    }

    assert "direction_ratio" in features


def test_burst_pattern_creates_finding():
    result = assess_metadata_exposure(
        make_feature_vector(
            burst_count=15.0,
        )
    )

    features = {
        finding["feature"]
        for finding in result["findings"]
    }

    assert "burst_pattern" in features


def test_missing_required_feature_is_rejected():
    features = make_feature_vector()

    features.pop("packet_count")

    try:
        assess_metadata_exposure(features)
    except ValueError as exc:
        assert "missing required fields" in str(exc)
    else:
        raise AssertionError(
            "Missing metadata features should be rejected"
        )


def test_findings_have_required_exposure_fields():
    result = assess_metadata_exposure(
        make_feature_vector(
            total_bytes=2_000_000.0,
            packets_per_second=50.0,
        )
    )

    assert result["findings"]

    for finding in result["findings"]:
        assert finding["feature"]
        assert finding["observed_value"] is not None
        assert finding["potential_inference"]
        assert finding["exposure_level"] in {
            "LOW",
            "MEDIUM",
            "HIGH",
        }
        assert finding["explanation"]
        assert finding["recommendation"]
        assert finding["provenance"] == "ASSESSED"
