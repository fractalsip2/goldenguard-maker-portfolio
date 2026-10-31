import os

from fastapi.testclient import TestClient

os.environ["TWILIO_VALIDATE_SIGNATURE"] = "false"
os.environ["GOLDENGUARD_MEMBER_LOOKUP_SECRET"] = "test-secret"

from api import app  # noqa: E402


def test_welcome_endpoint_rejects_wrong_secret(monkeypatch):
    monkeypatch.setenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", "test-secret")

    with TestClient(app) as client:
        response = client.post(
            "/internal/welcome-sms",
            headers={"x-goldenguard-internal-secret": "wrong"},
            json={
                "phone_number": "+12176932500",
                "first_name": "DJ",
                "language": "en",
            },
        )

    assert response.status_code == 401


def test_welcome_endpoint_sends_once_when_called(monkeypatch):
    monkeypatch.setenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", "test-secret")
    calls = []

    def fake_send(phone_number, first_name, language):
        calls.append((phone_number, first_name, language))
        return "SM123"

    monkeypatch.setattr("api.send_welcome_sms", fake_send)

    with TestClient(app) as client:
        response = client.post(
            "/internal/welcome-sms",
            headers={"x-goldenguard-internal-secret": "test-secret"},
            json={
                "phone_number": "+12176932500",
                "first_name": "DJ",
                "language": "en",
            },
        )

    assert response.status_code == 200
    assert response.json() == {"sent": True, "message_sid": "SM123"}
    assert calls == [("+12176932500", "DJ", "en")]
