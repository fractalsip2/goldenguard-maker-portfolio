"""Natural deterministic response composition for GoldenGuard.

No external language-model or translation API is used. Responses are assembled
from approved localized templates, the user's first name, concrete evidence,
and trusted links.
"""

from __future__ import annotations

from src.localization import (
    greeting_for,
    language_name,
    localized_evidence,
    normalize_locale,
    scam_label,
    text,
)


def clean_first_name(first_name: str | None) -> str:
    if not first_name:
        return ""
    candidate = first_name.strip().split()[0][:40]
    if not candidate.replace("-", "").replace("'", "").isalpha():
        return ""
    return candidate


def _sentence_case(value: str) -> str:
    value = value.strip()
    return value[:1].upper() + value[1:] if value else value


def _join_evidence(evidence: list[str], locale: str) -> str:
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in evidence:
        normalized = item.strip()
        key = normalized.casefold()
        if normalized and key not in seen:
            cleaned.append(_sentence_case(normalized) if locale not in {"zh-Hans", "zh-Hant"} else normalized)
            seen.add(key)

    if not cleaned:
        return ""
    if locale in {"zh-Hans", "zh-Hant"}:
        return " ".join(cleaned[:3])
    if len(cleaned) == 1:
        return cleaned[0]
    if len(cleaned) == 2:
        connectors = {
            "en": " Also, ",
            "es": " Además, ",
            "fr": " De plus, ",
            "de": " Außerdem: ",
            "vi": " Ngoài ra, ",
        }
        second = cleaned[1]
        if locale in {"en", "es", "fr", "vi"}:
            second = second[:1].lower() + second[1:]
        return cleaned[0] + connectors.get(locale, " ") + second
    return " ".join(cleaned[:3])


def _resource_lines(resources: list[dict]) -> list[str]:
    lines: list[str] = []
    for resource in resources:
        provider = resource.get("provider", "Trusted source")
        title = resource.get("title", "Scam guidance")
        url = resource.get("url", "")
        lines.append(f"{provider} — {title}")
        if url:
            lines.append(url)
    return lines


def compose_response(
    *,
    first_name: str | None,
    risk_level: str,
    risk_score: int = 0,
    scam_type: str,
    evidence: list[str],
    action: str,
    resources: list[dict],
    organization: str | None = None,
    seed_text: str = "",
    is_routine: bool = False,
    safe_code_notice: bool = False,
    preferred_language: str | None = None,
    signal_flags: list[str] | None = None,
) -> dict:
    del seed_text  # Kept for API compatibility with earlier builds.

    locale = normalize_locale(preferred_language)
    name = clean_first_name(first_name)
    greeting = greeting_for(name, locale)
    label = scam_label(scam_type, locale)

    translated_evidence = localized_evidence(
        locale=locale,
        signal_flags=signal_flags or [],
        organization=organization,
        fallback=evidence,
        limit=3,
    )
    explanation = _join_evidence(translated_evidence, locale)

    if risk_level == "LOW":
        if safe_code_notice:
            opening = text(locale, "safe_code", greeting=greeting)
            why_paragraph = text(locale, "safe_code_why")
            headline = text(locale, "headline_code")
        elif is_routine or not translated_evidence:
            opening = text(locale, "low_routine", greeting=greeting)
            why_paragraph = text(locale, "low_routine_why")
            headline = text(locale, "headline_low")
        else:
            opening = text(locale, "low_caution", greeting=greeting)
            why_paragraph = text(
                locale,
                "low_caution_why",
                evidence=explanation or text(locale, "why_generic"),
            )
            headline = text(locale, "headline_low_caution")
    else:
        opening_key = "high_opening" if risk_level == "HIGH" else "medium_opening"
        opening = text(locale, opening_key, greeting=greeting, label=label)
        if organization:
            opening += text(locale, "organization", organization=organization)

        why_paragraph = (
            text(locale, "why", evidence=explanation)
            if explanation
            else text(locale, "why_generic")
        )
        headline = text(
            locale,
            "headline_high" if risk_level == "HIGH" else "headline_medium",
        )

    paragraphs = [opening, why_paragraph, text(locale, "action", action=action)]

    resource_lines = _resource_lines(resources)
    if resource_lines:
        paragraphs.append(text(locale, "resources") + "\n" + "\n".join(resource_lines))

    return {
        "language": locale,
        "language_name": language_name(locale),
        "headline": headline,
        "opening": opening,
        "why": why_paragraph,
        "action": action,
        "resources": resources,
        "risk_score": risk_score,
        "full_text": "\n\n".join(paragraphs),
    }
