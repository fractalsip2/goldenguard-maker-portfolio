from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os

import httpx
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from src.detector import detect, load_model
from src.expanded_sms_locales import (
    EXTRA_LOCALES,
    language_name as extra_language_name,
    monthly_limit_text,
    normalize_extra_locale,
    system_text as extra_system_text,
)
from src.phone_profiles import claim_sms_interaction, get_member_profile, normalize_member_locale
from src.welcome_sms import send_welcome_sms
from src.rag.build_index import build_index
from src.localization import (
    SUPPORTED_LOCALES,
    language_name,
    system_message,
)
from src.sms_history import record_sms_history
from src.sms_gateway import format_sms_response


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_model()
    try:
        build_index()
    except (FileNotFoundError, ValueError):
        pass
    yield


app = FastAPI(
    title="GoldenGuard AI API",
    version="6.2.0-expanded-languages",
    lifespan=lifespan,
)


class AnalyzeRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)
    first_name: str | None = Field(default=None, max_length=40)
    language: str | None = Field(default="en", max_length=40)


class WelcomeSmsRequest(BaseModel):
    phone_number: str = Field(min_length=8, max_length=30)
    first_name: str | None = Field(default=None, max_length=40)
    language: str | None = Field(default="en", max_length=40)


def _env_truthy(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _request_url_for_signature(request: Request) -> str:
    """Return the exact public URL Twilio used when signing the request."""
    public_base_url = os.getenv("GOLDENGUARD_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if public_base_url:
        url = f"{public_base_url}{request.url.path}"
        if request.url.query:
            url += f"?{request.url.query}"
        return url
    return str(request.url)


def _validate_twilio_request(request: Request, form_data: dict[str, str]) -> None:
    if not _env_truthy("TWILIO_VALIDATE_SIGNATURE", default=False):
        return

    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")
    if not auth_token:
        raise HTTPException(
            status_code=500,
            detail="TWILIO_AUTH_TOKEN is required when signature validation is enabled.",
        )

    signature = request.headers.get("X-Twilio-Signature", "")
    signed_value = _request_url_for_signature(request)
    for key in sorted(form_data):
        signed_value += key + form_data[key]

    digest = hmac.new(
        auth_token.encode("utf-8"),
        signed_value.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    expected_signature = base64.b64encode(digest).decode("ascii")

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=403, detail="Invalid Twilio signature.")


def _validate_internal_request(request: Request) -> None:
    expected = os.getenv("GOLDENGUARD_MEMBER_LOOKUP_SECRET", "").strip()
    provided = request.headers.get("x-goldenguard-internal-secret", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Internal API secret is unavailable.")
    if not hmac.compare_digest(expected, provided):
        raise HTTPException(status_code=401, detail="Unauthorized.")


def _empty_twiml() -> Response:
    return Response(
        content='<?xml version="1.0" encoding="UTF-8"?><Response></Response>',
        media_type="application/xml",
    )


def _twiml_message(text: str) -> Response:
    escaped = html.escape(text, quote=False)
    twiml = f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{escaped}</Message></Response>'
    return Response(content=twiml, media_type="application/xml")


_MONTHLY_LIMIT_MESSAGES = {
    "en": "You’ve used all 20 GoldenGuard scam checks for this month. Your 20-check allowance resets on the 1st of next month.",
    "es": "Has usado las 20 revisiones de estafas de GoldenGuard de este mes. Tus 20 revisiones se restablecen el día 1 del próximo mes.",
    "fr": "Vous avez utilisé les 20 vérifications GoldenGuard de ce mois-ci. Votre quota de 20 se réinitialise le 1er du mois prochain.",
    "de": "Sie haben alle 20 GoldenGuard-Prüfungen für diesen Monat verwendet. Am 1. des nächsten Monats stehen wieder 20 zur Verfügung.",
    "zh-Hans": "您本月的 20 次 GoldenGuard 诈骗检查已用完。下月 1 日将重置为 20 次。",
    "zh-Hant": "您本月的 20 次 GoldenGuard 詐騙檢查已用完。下月 1 日將重設為 20 次。",
    "vi": "Bạn đã dùng hết 20 lượt kiểm tra lừa đảo GoldenGuard trong tháng này. Hạn mức 20 lượt sẽ đặt lại vào ngày 1 tháng tới.",
}


def _monthly_limit_message(locale: str) -> str:
    extra = normalize_extra_locale(locale)
    if extra:
        return monthly_limit_text(extra)
    return _MONTHLY_LIMIT_MESSAGES.get(locale, _MONTHLY_LIMIT_MESSAGES["en"])


def _system_sms_message(locale: str, key: str) -> str:
    extra = normalize_extra_locale(locale)
    if extra:
        return extra_system_text(extra, key)
    return system_message(locale, key)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "6.2.0-expanded-languages"}


@app.get("/languages")
def languages() -> dict[str, list[dict[str, str]]]:
    core = [
        {"code": locale, "label": language_name(locale)}
        for locale in SUPPORTED_LOCALES
    ]
    extra = [
        {"code": locale, "label": extra_language_name(locale)}
        for locale in EXTRA_LOCALES
    ]
    return {"languages": core + extra}


@app.post("/analyze")
async def analyze(request: AnalyzeRequest) -> dict:
    requested_locale = normalize_member_locale(request.language)
    analysis_locale = "en" if normalize_extra_locale(requested_locale) else requested_locale
    try:
        result = await run_in_threadpool(
            detect, request.message, request.first_name, analysis_locale
        )
        if requested_locale != analysis_locale:
            result["language"] = requested_locale
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.post("/internal/welcome-sms")
async def welcome_sms(payload: WelcomeSmsRequest, request: Request) -> dict[str, str | bool]:
    """Send the one-time welcome text after a consented account signup."""
    _validate_internal_request(request)
    try:
        message_sid = await run_in_threadpool(
            send_welcome_sms,
            payload.phone_number,
            payload.first_name,
            payload.language,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except (RuntimeError, httpx.HTTPError) as error:
        raise HTTPException(status_code=502, detail="Welcome SMS could not be sent.") from error

    return {"sent": True, "message_sid": message_sid}


@app.post("/twilio/sms")
async def receive_twilio_sms(request: Request, background_tasks: BackgroundTasks) -> Response:
    """Analyze an inbound Twilio SMS and reply with GoldenGuard's result."""
    form = await request.form()
    form_data = {str(key): str(value) for key, value in form.multi_items()}
    _validate_twilio_request(request, form_data)

    message_body = form_data.get("Body", "").strip()
    sender = form_data.get("From", "").strip()
    profile = await run_in_threadpool(get_member_profile, sender)
    if profile.get("authorized") is not True:
        # Unknown, inactive, or disabled numbers receive no outbound SMS.
        return _empty_twiml()

    first_name = profile.get("first_name")
    language = normalize_member_locale(
        str(profile.get("language")) if profile.get("language") is not None else None
    )

    if not message_body:
        return _twiml_message(_system_sms_message(language, "empty_sms"))

    message_sid = (form_data.get("MessageSid") or form_data.get("SmsSid") or "").strip()
    if not message_sid:
        return _twiml_message(_system_sms_message(language, "unavailable_sms"))

    usage = await run_in_threadpool(claim_sms_interaction, sender, message_sid)
    if usage.get("authorized") is not True:
        # Fail closed if the usage service/database cannot verify the request.
        return _twiml_message(_system_sms_message(language, "unavailable_sms"))
    if usage.get("allowed") is not True:
        return _twiml_message(_monthly_limit_message(language))

    analysis_language = "en" if normalize_extra_locale(language) else language
    try:
        result = await run_in_threadpool(
            detect, message_body, first_name, analysis_language
        )
        # Preserve the member's selected reply language even when one of the
        # expanded SMS locales uses the core English classifier internally.
        result["language"] = language
        # Preserve the submitted wording for message-specific details. The
        # untrusted message is never repeated as a link.
        result["original_message"] = message_body
    except ValueError:
        return _twiml_message(_system_sms_message(language, "invalid_sms"))
    except FileNotFoundError:
        return _twiml_message(_system_sms_message(language, "unavailable_sms"))

    response_text = format_sms_response(result)
    background_tasks.add_task(
        record_sms_history,
        sender,
        message_body,
        response_text,
        result,
        message_sid,
    )
    return _twiml_message(response_text)
