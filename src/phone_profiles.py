"""Member-profile lookup and usage gating for authorized SMS replies.

In production, the Render backend calls GoldenGuardUSA's private member APIs.
Lookups fail closed: a missing, disabled, unreachable, or over-limit profile is
never treated as an authorized scam-check interaction.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from src.expanded_sms_locales import normalize_extra_locale
from src.localization import DEFAULT_LOCALE, normalize_locale


DEFAULT_PROFILE_PATH = Path("data/phone_profiles.json")


def normalize_phone_number(value: str | None) -> str:
    if not value:
        return ""

    raw = value.strip()
    digits = re.sub(r"\D", "", raw)

    if raw.startswith("+") and 8 <= len(digits) <= 15:
        return "+" + digits
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    return ""


def normalize_member_locale(value: str | None) -> str:
    extra = normalize_extra_locale(value)
    return extra or normalize_locale(value)


def _unauthorized_profile() -> dict[str, str | bool | None]:
    return {
        "authorized": False,
        "first_name": None,
        "language": DEFAULT_LOCALE,
    }


def _internal_url(path_name: str) -> str:
    member_url = os.getenv("GOLDENGUARD_MEMBER_LOOKUP_URL", "").strip()
    if not member_url:
        return ""
    if member_url.endswith("/member-profile"):
        return member_url[: -len("/member-profile")] + f"/{path_name}"
    return ""


def _lookup_website_profile(
    normalized_phone: str,
) -> dict[str, str | bool | None]:
    url = os.getenv("GOLDENGUARD_MEMBER_LOOKUP_URL", "").strip()
    secret = os.getenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", "").strip()

    if not url or not secret:
        return _unauthorized_profile()

    try:
        with httpx.Client(timeout=8.0) as client:
            response = client.post(
                url,
                json={"phone_number": normalized_phone},
                headers={
                    "x-goldenguard-internal-secret": secret,
                    "accept": "application/json",
                },
            )
        if response.status_code != 200:
            return _unauthorized_profile()
        payload = response.json()
    except (httpx.HTTPError, ValueError, TypeError):
        return _unauthorized_profile()

    if not isinstance(payload, dict) or payload.get("authorized") is not True:
        return _unauthorized_profile()

    raw_name = payload.get("first_name")
    first_name = raw_name.strip()[:40] if isinstance(raw_name, str) else None
    raw_language = payload.get("language")
    language = normalize_member_locale(raw_language if isinstance(raw_language, str) else None)

    return {
        "authorized": True,
        "first_name": first_name or None,
        "language": language,
    }


def claim_sms_interaction(
    phone_number: str | None, twilio_message_sid: str | None
) -> dict[str, int | bool]:
    """Atomically claim one monthly scam-check interaction for a member.

    Production delegates the counter to the website/database. Twilio retries are
    idempotent because the website keys usage by Message SID. Local profile mode
    stays unrestricted so development tests do not depend on a database.
    """
    normalized = normalize_phone_number(phone_number)
    message_sid = (twilio_message_sid or "").strip()[:80]
    if not normalized or not message_sid:
        return {"authorized": False, "allowed": False, "limit": 20, "used": 0, "remaining": 0}

    member_url = os.getenv("GOLDENGUARD_MEMBER_LOOKUP_URL", "").strip()
    if not member_url:
        if _env_truthy("GOLDENGUARD_ALLOW_LOCAL_PROFILES", default=True):
            return {"authorized": True, "allowed": True, "limit": 20, "used": 0, "remaining": 20}
        return {"authorized": False, "allowed": False, "limit": 20, "used": 0, "remaining": 0}

    url = os.getenv("GOLDENGUARD_SMS_USAGE_URL", "").strip() or _internal_url("sms-usage")
    secret = os.getenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", "").strip()
    if not url or not secret:
        return {"authorized": False, "allowed": False, "limit": 20, "used": 0, "remaining": 0}

    try:
        with httpx.Client(timeout=8.0) as client:
            response = client.post(
                url,
                json={
                    "phone_number": normalized,
                    "twilio_message_sid": message_sid,
                },
                headers={
                    "x-goldenguard-internal-secret": secret,
                    "accept": "application/json",
                },
            )
        if response.status_code != 200:
            return {"authorized": False, "allowed": False, "limit": 20, "used": 0, "remaining": 0}
        payload = response.json()
    except (httpx.HTTPError, ValueError, TypeError):
        return {"authorized": False, "allowed": False, "limit": 20, "used": 0, "remaining": 0}

    if not isinstance(payload, dict):
        return {"authorized": False, "allowed": False, "limit": 20, "used": 0, "remaining": 0}

    return {
        "authorized": payload.get("authorized") is True,
        "allowed": payload.get("allowed") is True,
        "limit": int(payload.get("limit") or 20),
        "used": int(payload.get("used") or 0),
        "remaining": int(payload.get("remaining") or 0),
    }


def _profile_path() -> Path:
    configured = os.getenv("GOLDENGUARD_PHONE_PROFILES")
    return Path(configured) if configured else DEFAULT_PROFILE_PATH


@lru_cache(maxsize=1)
def _load_local_profiles() -> dict[str, Any]:
    path = _profile_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def clear_profile_cache() -> None:
    _load_local_profiles.cache_clear()


def _env_truthy(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _lookup_local_profile(
    normalized_phone: str,
) -> dict[str, str | bool | None]:
    value = _load_local_profiles().get(normalized_phone)
    if value is None:
        return _unauthorized_profile()

    first_name: str | None = None
    language = DEFAULT_LOCALE
    authorized = True

    if isinstance(value, str):
        first_name = value.strip() or None
    elif isinstance(value, dict):
        authorized = value.get("authorized", True) is True
        raw_name = value.get("first_name")
        if isinstance(raw_name, str):
            first_name = raw_name.strip() or None
        raw_language = value.get("language") or value.get("preferred_language")
        if isinstance(raw_language, str):
            language = normalize_member_locale(raw_language)
    else:
        authorized = False

    return {
        "authorized": authorized,
        "first_name": first_name,
        "language": language,
    }


def get_member_profile(phone_number: str | None) -> dict[str, str | bool | None]:
    """Return member authorization, first name, and preferred language."""
    normalized = normalize_phone_number(phone_number)
    if not normalized:
        return _unauthorized_profile()

    if os.getenv("GOLDENGUARD_MEMBER_LOOKUP_URL", "").strip():
        return _lookup_website_profile(normalized)

    if _env_truthy("GOLDENGUARD_ALLOW_LOCAL_PROFILES", default=True):
        return _lookup_local_profile(normalized)

    return _unauthorized_profile()


def get_profile(phone_number: str | None) -> dict[str, str | None]:
    """Backward-compatible name/language lookup used by older local tests."""
    profile = get_member_profile(phone_number)
    return {
        "first_name": profile.get("first_name") if isinstance(profile.get("first_name"), str) else None,
        "language": str(profile.get("language") or DEFAULT_LOCALE),
    }


def get_first_name(phone_number: str | None) -> str | None:
    return get_profile(phone_number)["first_name"]


def get_preferred_language(phone_number: str | None) -> str:
    return str(get_profile(phone_number)["language"] or DEFAULT_LOCALE)
