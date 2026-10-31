from src.detector import detect


def test_detector_returns_complete_mvp_response():
    result = detect(
        "USPS: your package cannot be delivered. Pay a small fee at http://delivery-help.xyz",
        "Robert",
    )

    assert result["risk_level"] in {"MEDIUM", "HIGH"}
    assert result["scam_type"] == "package_delivery"
    assert result["helpful_resources"]
    assert result["personalized_response"].startswith("Robert,")
    assert "http" in result["personalized_response"]
