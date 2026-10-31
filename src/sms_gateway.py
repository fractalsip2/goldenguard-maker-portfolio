"""SMS formatting gateway for core and expanded deterministic locales."""

from __future__ import annotations

from src.expanded_sms_locales import format_extra_sms, normalize_extra_locale
from src.sms_response import (
    _finish_without_mid_sentence_cutoff,
    _max_chars,
    _resource,
    format_sms_response as format_core_sms_response,
)


def format_sms_response(result: dict) -> str:
    extra_locale = normalize_extra_locale(
        str(result.get("language")) if result.get("language") is not None else None
    )
    if not extra_locale:
        return format_core_sms_response(result)

    text = format_extra_sms(result, extra_locale, _resource(result))
    return _finish_without_mid_sentence_cutoff(text, _max_chars(extra_locale))
