from src.sms_history import _history_url, record_sms_history


def test_history_url_is_derived_from_member_lookup(monkeypatch):
    monkeypatch.delenv("GOLDENGUARD_SMS_HISTORY_URL", raising=False)
    monkeypatch.setenv(
        "GOLDENGUARD_MEMBER_LOOKUP_URL",
        "https://goldenguardusa.com/api/internal/member-profile",
    )

    assert _history_url() == "https://goldenguardusa.com/api/internal/sms-history"


def test_record_history_posts_expected_payload(monkeypatch):
    captured = {}

    class Response:
        status_code = 200

    class Client:
        def __init__(self, timeout):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, json, headers):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return Response()

    monkeypatch.setattr("src.sms_history.httpx.Client", Client)
    monkeypatch.setenv("GOLDENGUARD_SMS_HISTORY_URL", "https://example.com/history")
    monkeypatch.setenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", "shared-secret")

    recorded = record_sms_history(
        "+12175550123",
        "USPS says pay $2.99",
        "DJ, this looks like a fake USPS text.",
        {"risk_level": "HIGH", "scam_type": "package_delivery", "language": "en"},
        "SM123",
    )

    assert recorded is True
    assert captured["url"] == "https://example.com/history"
    assert captured["headers"]["x-goldenguard-internal-secret"] == "shared-secret"
    assert captured["json"]["phone_number"] == "+12175550123"
    assert captured["json"]["risk_level"] == "HIGH"
    assert captured["json"]["twilio_message_sid"] == "SM123"
