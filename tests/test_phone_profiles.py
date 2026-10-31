from src.phone_profiles import get_member_profile, normalize_phone_number


def test_normalize_phone_number():
    assert normalize_phone_number("(217) 555-1234") == "+12175551234"
    assert normalize_phone_number("+44 20 7946 0958") == "+442079460958"
    assert normalize_phone_number("bad") == ""


def test_website_lookup_authorizes_member(monkeypatch):
    monkeypatch.setenv("GOLDENGUARD_MEMBER_LOOKUP_URL", "https://example.test/member")
    monkeypatch.setenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", "secret")

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"authorized": True, "first_name": "María", "language": "es"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr("src.phone_profiles.httpx.Client", lambda **_kwargs: Client())
    profile = get_member_profile("2175551234")

    assert profile == {"authorized": True, "first_name": "María", "language": "es"}


def test_lookup_fails_closed_without_configuration(monkeypatch):
    monkeypatch.delenv("GOLDENGUARD_MEMBER_LOOKUP_URL", raising=False)
    monkeypatch.delenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", raising=False)
    monkeypatch.setenv("GOLDENGUARD_ALLOW_LOCAL_PROFILES", "false")

    profile = get_member_profile("2175551234")
    assert profile["authorized"] is False
