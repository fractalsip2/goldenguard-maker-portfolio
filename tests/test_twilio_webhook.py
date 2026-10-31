import os

from fastapi.testclient import TestClient

os.environ["TWILIO_VALIDATE_SIGNATURE"] = "false"

from api import app  # noqa: E402


def test_unknown_number_receives_empty_twiml(monkeypatch):
    def unauthorized(_number):
        return {"authorized": False, "first_name": None, "language": "en"}

    monkeypatch.setattr("api.get_member_profile", unauthorized)
    monkeypatch.setattr("api.detect", lambda *_args: (_ for _ in ()).throw(AssertionError("detector should not run")))

    with TestClient(app) as client:
        response = client.post(
            "/twilio/sms",
            data={"From": "+12175550123", "Body": "hello"},
        )

    assert response.status_code == 200
    assert "<Response></Response>" in response.text
    assert "<Message>" not in response.text


def test_registered_number_receives_personalized_localized_twiml(monkeypatch):
    recorded = []

    def authorized(_number):
        return {"authorized": True, "first_name": "Robert", "language": "es"}

    monkeypatch.setattr("api.get_member_profile", authorized)
    monkeypatch.setattr(
        "api.record_sms_history",
        lambda *args: recorded.append(args) or True,
    )
    monkeypatch.setattr(
        "api.detect",
        lambda message, first_name, language: {
            "first_name": first_name,
            "language": language,
            "risk_level": "HIGH",
            "scam_type": "bank_impersonation",
            "organization": "Chase",
            "signal_flags": ["credential_request"],
            "immediate_action": "No use el enlace. Abra la aplicación oficial de su banco.",
            "helpful_resources": [],
            "personalized_response": f"{first_name}: {message}",
        },
    )

    with TestClient(app) as client:
        response = client.post(
            "/twilio/sms",
            data={
                "From": "+12175550123",
                "To": "+12175550999",
                "Body": "Your account is locked",
                "MessageSid": "SM_TEST_123",
            },
        )

    assert response.status_code == 200
    assert "Robert" in response.text
    assert "RIESGO ALTO" in response.text
    assert "aplicación oficial" in response.text
    assert len(recorded) == 1
    assert recorded[0][0] == "+12175550123"
    assert recorded[0][1] == "Your account is locked"
    assert recorded[0][4] == "SM_TEST_123"
