"""One-time welcome SMS delivery for newly created GoldenGuard accounts."""

from __future__ import annotations

import os
import re

import httpx

from src.expanded_sms_locales import normalize_extra_locale, welcome_text
from src.localization import normalize_locale
from src.phone_profiles import normalize_phone_number


_WELCOME_TEMPLATES = {
    "en": (
        "Welcome to GoldenGuard, {name}! SMS protection is active. Send "
        "suspicious texts here and we'll check for scam signs. You have up to "
        "20 scam checks per month. Reply STOP to opt out or HELP for help."
    ),
    "es": (
        "Bienvenido a GoldenGuard, {name}. Tu protección SMS está activa. Envía "
        "mensajes sospechosos aquí para revisar señales de estafa. Tienes hasta "
        "20 revisiones al mes. STOP cancela; HELP ayuda."
    ),
    "fr": (
        "Bienvenue sur GoldenGuard, {name}. Protection SMS active. Envoyez ici "
        "les messages suspects. Vous avez jusqu'à 20 vérifications par mois. "
        "STOP pour vous désabonner; HELP pour l’aide."
    ),
    "de": (
        "Willkommen bei GoldenGuard, {name}. SMS-Schutz ist aktiv. Senden Sie "
        "verdächtige Nachrichten hierher. Bis zu 20 Prüfungen pro Monat. "
        "STOP zum Abmelden; HELP für Hilfe."
    ),
    "zh-Hans": (
        "{name}，欢迎使用 GoldenGuard！您的短信保护已启用。请将可疑短信发送到这里，"
        "我们会检查诈骗警示信号。每月最多可检查20次。回复 STOP 可退订，回复 HELP 可获取帮助。"
    ),
    "zh-Hant": (
        "{name}，歡迎使用 GoldenGuard！您的簡訊保護已啟用。請將可疑簡訊傳送到這裡，"
        "我們會檢查詐騙警示訊號。每月最多可檢查20次。回覆 STOP 可退訂，回覆 HELP 可取得協助。"
    ),
    "vi": (
        "Chào mừng đến GoldenGuard, {name}. Bảo vệ SMS đã bật. Gửi tin nhắn "
        "đáng ngờ vào đây. Bạn có tối đa 20 lượt kiểm tra mỗi tháng. "
        "STOP để hủy; HELP để được trợ giúp."
    ),
}


def _clean_first_name(value: str | None) -> str:
    cleaned = re.sub(r"[\r\n\t]+", " ", (value or "").strip())
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:40] or "there"


def build_welcome_message(first_name: str | None, language: str | None) -> str:
    """Return the approved welcome wording in the member's chosen language."""
    extra_locale = normalize_extra_locale(language)
    if extra_locale:
        return welcome_text(extra_locale, _clean_first_name(first_name))

    locale = normalize_locale(language)
    template = _WELCOME_TEMPLATES.get(locale, _WELCOME_TEMPLATES["en"])
    return template.format(name=_clean_first_name(first_name))


def send_welcome_sms(
    phone_number: str,
    first_name: str | None,
    language: str | None,
) -> str:
    """Send the welcome SMS through Twilio and return its Message SID."""
    normalized_phone = normalize_phone_number(phone_number)
    if not normalized_phone:
        raise ValueError("A valid destination phone number is required.")

    account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    messaging_service_sid = os.getenv("TWILIO_MESSAGING_SERVICE_SID", "").strip()
    from_number = normalize_phone_number(os.getenv("TWILIO_FROM_NUMBER", ""))

    if not account_sid or not auth_token:
        raise RuntimeError("Twilio outbound credentials are not configured.")
    if not messaging_service_sid and not from_number:
        raise RuntimeError(
            "TWILIO_MESSAGING_SERVICE_SID or TWILIO_FROM_NUMBER is required."
        )

    payload = {
        "To": normalized_phone,
        "Body": build_welcome_message(first_name, language),
    }
    if messaging_service_sid:
        payload["MessagingServiceSid"] = messaging_service_sid
    else:
        payload["From"] = from_number

    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    with httpx.Client(timeout=12.0) as client:
        response = client.post(url, data=payload, auth=(account_sid, auth_token))
        response.raise_for_status()
        data = response.json()

    message_sid = data.get("sid") if isinstance(data, dict) else None
    if not isinstance(message_sid, str) or not message_sid:
        raise RuntimeError("Twilio did not return a message SID.")
    return message_sid
