from fastapi.testclient import TestClient

from api import app


def test_analyze_accepts_language():
    with TestClient(app) as client:
        response = client.post(
            "/analyze",
            json={
                "message": "USPS: pay a redelivery fee at usps-help.xyz",
                "first_name": "Marie",
                "language": "fr",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["language"] == "fr"
    assert "Que faire maintenant" in payload["personalized_response"]


def test_languages_endpoint_lists_signup_options():
    with TestClient(app) as client:
        response = client.get("/languages")

    assert response.status_code == 200
    values = {item["code"] for item in response.json()["languages"]}
    assert values == {
        "en",
        "es",
        "fr",
        "de",
        "pt",
        "it",
        "zh-Hans",
        "zh-Hant",
        "vi",
        "ja",
        "ko",
        "ar",
        "hi",
        "tl",
        "ru",
    }
