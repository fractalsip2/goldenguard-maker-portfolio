"""Persist completed SMS analyses to the member website without delaying Twilio."""

from __future__ import annotations

import os
from typing import Any

import httpx


def _history_url() -> str:
    configured = os.getenv("GOLDENGUARD_SMS_HISTORY_URL", "").strip()
    if configured:
        return configured

    member_lookup_url = os.getenv("GOLDENGUARD_MEMBER_LOOKUP_URL", "").strip()
    if member_lookup_url.endswith("/member-profile"):
        return member_lookup_url.rsplit("/", 1)[0] + "/sms-history"
    return ""


def record_sms_history(
    phone_number: str,
    inbound_message: str,
    outbound_response: str,
    result: dict[str, Any],
    twilio_message_sid: str | None = None,
) -> bool:
    """Record one completed check. Fail quietly so SMS delivery still succeeds."""
    url = _history_url()
    secret = os.getenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", "").strip()
    if not url or not secret:
        return False

    payload = {
        "phone_number": phone_number,
        "inbound_message": inbound_message,
        "outbound_response": outbound_response,
        "risk_level": str(result.get("risk_level", "UNKNOWN")),
        "scam_type": str(result.get("scam_type", "unknown")),
        "language": str(result.get("language", "en")),
        "twilio_message_sid": twilio_message_sid or None,
    }

    try:
        with httpx.Client(timeout=8.0) as client:
            response = client.post(
                url,
                json=payload,
                headers={
                    "x-goldenguard-internal-secret": secret,
                    "accept": "application/json",
                },
            )
        return 200 <= response.status_code < 300
    except httpx.HTTPError:
        return False
