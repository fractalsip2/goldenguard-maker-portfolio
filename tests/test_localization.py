import json

import pytest

from src.detector import detect
from src.localization import SUPPORTED_LOCALES, normalize_locale
from src.phone_profiles import clear_profile_cache, get_profile
from src.sms_response import format_sms_response


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("English", "en"),
        ("Español", "es"),
        ("Français", "fr"),
        ("Deutsch", "de"),
        ("简体中文", "zh-Hans"),
        ("繁體中文", "zh-Hant"),
        ("Tiếng Việt", "vi"),
        ("unknown", "en"),
    ],
)
def test_language_aliases(value, expected):
    assert normalize_locale(value) == expected


def test_phone_profile_returns_name_and_language(tmp_path, monkeypatch):
    profile_file = tmp_path / "profiles.json"
    profile_file.write_text(
        json.dumps(
            {
                "+12175550123": {
                    "first_name": "María",
                    "preferred_language": "Español",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GOLDENGUARD_PHONE_PROFILES", str(profile_file))
    clear_profile_cache()
    try:
        assert get_profile("217-555-0123") == {
            "first_name": "María",
            "language": "es",
        }
    finally:
        clear_profile_cache()


@pytest.mark.parametrize(
    ("locale", "expected_phrase"),
    [
        ("en", "What to do now"),
        ("es", "Qué hacer ahora"),
        ("fr", "Que faire maintenant"),
        ("de", "Was Sie jetzt tun sollten"),
        ("zh-Hans", "现在该怎么做"),
        ("zh-Hant", "現在該怎麼做"),
        ("vi", "Việc cần làm ngay"),
    ],
)
def test_detailed_response_is_localized(locale, expected_phrase):
    result = detect(
        "Chase alert: your account is suspended. Verify at chase-help.xyz",
        "Alex",
        locale,
    )
    assert result["language"] == locale
    assert expected_phrase in result["personalized_response"]
    assert result["risk_level"] == "HIGH"
    assert result["helpful_resources"]


@pytest.mark.parametrize("locale", SUPPORTED_LOCALES)
def test_sms_reply_is_complete_and_does_not_repeat_submitted_domain(locale):
    result = detect(
        "Chase alert: your account is suspended. Verify at chase-help.xyz",
        "Alex",
        locale,
    )
    sms = format_sms_response(result)
    assert "chase-help.xyz" not in sms
    # Full safety guidance may span several carrier SMS segments; the formatter
    # now preserves the explanation and official resource instead of clipping
    # every reply to the old 306-character two-segment limit.
    assert len(sms) <= 600
    assert "https://" in sms
    assert not sms.endswith("…")


def test_low_risk_sms_has_no_resource_link():
    result = detect("Hey, are we still getting dinner Saturday? My treat.", "Bob", "en")
    sms = format_sms_response(result)
    assert result["risk_level"] == "LOW"
    assert "https://" not in sms
    assert "LOW RISK" in sms
