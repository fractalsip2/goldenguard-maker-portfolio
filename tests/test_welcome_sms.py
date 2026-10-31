import pytest

from src.welcome_sms import build_welcome_message, send_welcome_sms


def test_english_welcome_is_personalized_and_includes_opt_out_help():
    message = build_welcome_message("DJ", "en")

    assert "DJ" in message
    assert "SMS protection is active" in message
    assert "STOP" in message
    assert "HELP" in message


def test_welcome_uses_selected_language():
    message = build_welcome_message("DJ", "es")

    assert "Bienvenido" in message
    assert "DJ" in message
    assert "STOP" in message
    assert "HELP" in message


def test_welcome_strips_line_breaks_from_name():
    message = build_welcome_message("DJ\nInjected", "en")

    assert "\n" not in message
    assert "DJ Injected" in message


def test_send_welcome_uses_messaging_service(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC123")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "secret")
    monkeypatch.setenv("TWILIO_MESSAGING_SERVICE_SID", "MG123")
    monkeypatch.delenv("TWILIO_FROM_NUMBER", raising=False)

    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"sid": "SM123"}

    class FakeClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, data, auth):
            captured.update(url=url, data=data, auth=auth)
            return FakeResponse()

    monkeypatch.setattr("src.welcome_sms.httpx.Client", FakeClient)

    sid = send_welcome_sms("217-693-2500", "DJ", "en")

    assert sid == "SM123"
    assert captured["data"]["To"] == "+12176932500"
    assert captured["data"]["MessagingServiceSid"] == "MG123"
    assert "From" not in captured["data"]
    assert captured["auth"] == ("AC123", "secret")


def test_send_welcome_requires_outbound_credentials(monkeypatch):
    monkeypatch.delenv("TWILIO_ACCOUNT_SID", raising=False)
    monkeypatch.delenv("TWILIO_AUTH_TOKEN", raising=False)

    with pytest.raises(RuntimeError):
        send_welcome_sms("+12176932500", "DJ", "en")
