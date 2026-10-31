"""Personalized, localized GoldenGuard SMS responses.

Responses are allowed enough room to finish the explanation instead of being
artificially clipped to two SMS segments. Twilio/carriers can deliver a longer
message as concatenated SMS segments; GoldenGuard still applies a conservative
upper bound to avoid runaway output.
"""

from __future__ import annotations

import os
import re

from src.localization import normalize_locale, scam_label
from src.response import clean_first_name


RISK_LABELS = {
    "en": {"HIGH": "HIGH RISK", "MEDIUM": "SUSPICIOUS", "LOW": "LOW RISK"},
    "es": {"HIGH": "RIESGO ALTO", "MEDIUM": "SOSPECHOSO", "LOW": "RIESGO BAJO"},
    "fr": {"HIGH": "RISQUE ÉLEVÉ", "MEDIUM": "SUSPECT", "LOW": "RISQUE FAIBLE"},
    "de": {"HIGH": "HOHES RISIKO", "MEDIUM": "VERDÄCHTIG", "LOW": "GERINGES RISIKO"},
    "zh-Hans": {"HIGH": "高风险", "MEDIUM": "可疑", "LOW": "低风险"},
    "zh-Hant": {"HIGH": "高風險", "MEDIUM": "可疑", "LOW": "低風險"},
    "vi": {"HIGH": "RỦI RO CAO", "MEDIUM": "ĐÁNG NGỜ", "LOW": "RỦI RO THẤP"},
}

LOW_TEXT = {
    "en": "No strong scam signs found. If you recognize the sender and the message makes sense, it is probably okay. Otherwise, verify before replying.",
    "es": "No se encontraron señales claras de estafa. Si reconoce al remitente y el mensaje tiene sentido, probablemente sea legítimo. Si no, verifique antes de responder.",
    "fr": "Aucun signe clair d'arnaque. Si vous reconnaissez l'expéditeur et que le message est cohérent, il est probablement légitime. Sinon, vérifiez avant de répondre.",
    "de": "Keine deutlichen Betrugsanzeichen. Wenn Sie den Absender kennen und die Nachricht passt, ist sie wahrscheinlich in Ordnung. Sonst zuerst prüfen.",
    "zh-Hans": "未发现明显诈骗迹象。如果您认识发件人且内容合理，消息很可能没有问题；否则请先核实再回复。",
    "zh-Hant": "未發現明顯詐騙跡象。如果您認識寄件者且內容合理，訊息很可能沒有問題；否則請先核實再回覆。",
    "vi": "Không thấy dấu hiệu lừa đảo rõ ràng. Nếu bạn nhận ra người gửi và nội dung hợp lý, tin nhắn có lẽ an toàn. Nếu không, hãy xác minh trước khi trả lời.",
}

ASSESSMENT = {
    "en": {"HIGH": "This is likely {label}.", "MEDIUM": "This may be {label}."},
    "es": {"HIGH": "Probablemente sea {label}.", "MEDIUM": "Podría ser {label}."},
    "fr": {"HIGH": "Il s'agit probablement de {label}.", "MEDIUM": "Il pourrait s'agir de {label}."},
    "de": {"HIGH": "Dies ist wahrscheinlich {label}.", "MEDIUM": "Dies könnte {label} sein."},
    "zh-Hans": {"HIGH": "这很可能是{label}。", "MEDIUM": "这可能是{label}。"},
    "zh-Hant": {"HIGH": "這很可能是{label}。", "MEDIUM": "這可能是{label}。"},
    "vi": {"HIGH": "Đây rất có thể là {label}.", "MEDIUM": "Đây có thể là {label}."},
}

RESOURCE_LABEL = {
    "en": "Learn More",
    "es": "Más información",
    "fr": "En savoir plus",
    "de": "Mehr erfahren",
    "zh-Hans": "了解更多",
    "zh-Hant": "了解更多",
    "vi": "Tìm hiểu thêm",
}

SCAM_RESOURCE_LIBRARY = {
    "bank_impersonation": {
        "provider": "AARP",
        "title": "Bank Impersonation Scams",
        "url": "https://www.aarp.org/money/scams-fraud/online-banking-fraud",
    },
    "account_takeover": {
        "provider": "FTC",
        "title": "Verification Code & Phishing Scams",
        "url": "https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams",
    },
    "gift_card": {
        "provider": "FTC",
        "title": "Gift Card Scams",
        "url": "https://consumer.ftc.gov/articles/avoiding-and-reporting-gift-card-scams",
    },
    "grandparent_impersonation": {
        "provider": "AARP",
        "title": "Grandparent Impersonation Scams",
        "url": "https://www.aarp.org/money/scams-fraud/grandparent/",
    },
    "family_emergency": {
        "provider": "FTC",
        "title": "Family Emergency Scams",
        "url": "https://consumer.ftc.gov/articles/scammers-use-fake-emergencies-steal-your-money",
    },
    "government_impersonation": {
        "provider": "FTC",
        "title": "Government Impersonation Scams",
        "url": "https://consumer.ftc.gov/articles/how-avoid-government-impersonation-scam",
    },
    "usps_delivery": {
        "provider": "USPIS",
        "title": "USPS Package-Tracking Text Scams",
        "url": "https://www.uspis.gov/news/scam-article/smishing-package-tracking-text-scams",
    },
    "package_delivery": {
        "provider": "FTC",
        "title": "Package-Delivery Phishing Scams",
        "url": "https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams",
    },
    "romance": {
        "provider": "FTC",
        "title": "Romance Scams",
        "url": "https://consumer.ftc.gov/articles/what-know-about-romance-scams",
    },
    "investment": {
        "provider": "FTC",
        "title": "Investment Scams",
        "url": "https://consumer.ftc.gov/articles/investment-scams",
    },
    "cryptocurrency": {
        "provider": "FTC",
        "title": "Cryptocurrency Scams",
        "url": "https://consumer.ftc.gov/articles/what-know-about-cryptocurrency-scams",
    },
    "tech_support": {
        "provider": "FTC",
        "title": "Tech Support Scams",
        "url": "https://consumer.ftc.gov/articles/how-spot-avoid-and-report-tech-support-scams",
    },
    "prize_sweepstakes": {
        "provider": "FTC",
        "title": "Prize, Sweepstakes & Lottery Scams",
        "url": "https://consumer.ftc.gov/articles/fake-prize-sweepstakes-and-lottery-scams",
    },
    "employment": {
        "provider": "FTC",
        "title": "Job Scams",
        "url": "https://consumer.ftc.gov/articles/job-scams",
    },
    "marketplace": {
        "provider": "FTC",
        "title": "Online Marketplace Scams",
        "url": "https://consumer.ftc.gov/consumer-alerts/2022/07/selling-stuff-online-heres-how-avoid-scam",
    },
    "toll_payment": {
        "provider": "FTC",
        "title": "Unpaid-Toll Text Scams",
        "url": "https://consumer.ftc.gov/consumer-alerts/2025/01/got-text-about-unpaid-tolls-its-probably-scam",
    },
    "unknown": {
        "provider": "FTC",
        "title": "Avoiding and Reporting Scams",
        "url": "https://consumer.ftc.gov/scams",
    },
}

SUPPORTED_RESOURCE_CATEGORIES = {
    "bank_impersonation",
    "account_takeover",
    "gift_card",
    "grandparent_emergency",
    "government_impersonation",
    "package_delivery",
    "romance",
    "investment_crypto",
    "tech_support",
    "prize_sweepstakes",
    "employment",
    "marketplace",
    "toll_payment",
    "unknown",
}

AMOUNT_RE = re.compile(r"\$\s?\d[\d,]*(?:\.\d{1,2})?")
PERCENT_RE = re.compile(r"\b\d{1,3}(?:\.\d+)?%")


def _env_truthy(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _max_chars(locale: str) -> int:
    del locale
    # 600 characters is enough for GoldenGuard's complete explanation plus one
    # official resource in normal cases. It may span multiple carrier segments,
    # which is preferable to silently cutting off safety guidance.
    try:
        return max(306, min(1200, int(os.getenv("GOLDENGUARD_SMS_MAX_CHARS", "600"))))
    except ValueError:
        return 600


def _prefix(first_name: str | None, locale: str) -> str:
    name = clean_first_name(first_name)
    if not name:
        return ""
    separator = "，" if locale in {"zh-Hans", "zh-Hant"} else ", "
    return f"{name}{separator}"


def _natural_name_prefix(first_name: str | None) -> str:
    name = clean_first_name(first_name)
    return f"{name}, " if name else ""


def _resource_key(result: dict) -> str:
    scam_type = str(result.get("scam_type", "unknown"))
    message = str(result.get("original_message") or "").casefold()

    if scam_type == "grandparent_emergency":
        terms = (
            "grandma", "grandpa", "grandmother", "grandfather",
            "grandson", "granddaughter", "grandchild",
        )
        return "grandparent_impersonation" if any(term in message for term in terms) else "family_emergency"
    if scam_type == "package_delivery":
        return "usps_delivery" if "usps" in message or "postal service" in message else "package_delivery"
    if scam_type == "investment_crypto":
        crypto_terms = ("bitcoin", "crypto", "cryptocurrency", "wallet", "btc", "ethereum")
        return "cryptocurrency" if any(term in message for term in crypto_terms) else "investment"
    return scam_type if scam_type in SCAM_RESOURCE_LIBRARY else "unknown"


def _resource(result: dict) -> dict[str, str] | None:
    if not _env_truthy("GOLDENGUARD_SMS_INCLUDE_URLS", True):
        return None
    return SCAM_RESOURCE_LIBRARY.get(_resource_key(result), SCAM_RESOURCE_LIBRARY["unknown"])


def _first_amount(message: str) -> str:
    match = AMOUNT_RE.search(message)
    return match.group(0).replace(" ", "") if match else ""


def _first_percentage(message: str) -> str:
    match = PERCENT_RE.search(message)
    return match.group(0) if match else ""


def _organization(result: dict, fallback: str) -> str:
    organization = str(result.get("organization") or "").strip()
    return organization or fallback


def _has_any(message: str, terms: tuple[str, ...]) -> bool:
    lowered = message.casefold()
    return any(term in lowered for term in terms)


def _english_specific_body(result: dict) -> str:
    message = str(result.get("original_message") or "")
    scam_type = str(result.get("scam_type", "unknown"))
    name = _natural_name_prefix(result.get("first_name"))
    amount = _first_amount(message)
    percent = _first_percentage(message)
    flags = set(result.get("signal_flags") or [])

    if scam_type == "package_delivery":
        carrier = _organization(result, "delivery company")
        signs: list[str] = []
        if amount:
            signs.append(f"the {amount} fee")
        if _has_any(message, ("link", "tap", "click")) or result.get("urls_found"):
            signs.append("the payment link")
        sign_text = " and ".join(signs) if signs else "the unexpected delivery request"
        official = {
            "USPS": "the USPS app or at usps.com",
            "UPS": "the UPS app or at ups.com",
            "FedEx": "the FedEx app or at fedex.com",
        }.get(carrier, "the carrier's official app or website")
        return (
            f"{name}this looks like a fake {carrier} redelivery text. "
            f"{sign_text[:1].upper() + sign_text[1:]} are common phishing signs. "
            f"Don't tap it or enter card details. Check the package only in {official}."
        )

    if scam_type in {"bank_impersonation", "account_takeover"}:
        bank = _organization(result, "bank")
        claim = "locked-account claim" if _has_any(message, ("locked", "suspended", "frozen")) else "unexpected account alert"
        request = "request for your password" if _has_any(message, ("password", "code", "verify", "confirm")) else "request to act"
        return (
            f"{name}this looks like a fake {bank} alert. The {claim} and {request} are phishing signs. "
            "Don't reply or share details. Check the official app or call the number on your card."
        )

    if scam_type == "grandparent_emergency":
        details: list[str] = []
        if amount:
            details.append(f"the {amount} request")
        if _has_any(message, ("bail", "jail", "arrested", "hospital", "emergency")):
            details.append("the emergency story")
        if "secrecy" in flags or _has_any(message, ("don't tell", "do not tell", "keep this secret")):
            details.append("the demand for secrecy")
        warning = ", ".join(details) if details else "The urgent money request"
        return (
            f"{name}this looks like a family-emergency scam. {warning[:1].upper() + warning[1:]} are major warning signs. "
            "Don't send money. Call your relative or another family member using a number you already know."
        )

    if scam_type == "gift_card":
        detail = f"The {amount} demand" if amount else "The payment demand"
        return (
            f"{name}this looks like a gift-card scam. {detail} and request for card codes are major warning signs. "
            "Don't buy the cards or share the numbers, PINs, or photos. Verify the request another way."
        )

    if scam_type == "government_impersonation":
        agency = _organization(result, "government agency")
        detail = "threat of arrest" if _has_any(message, ("arrest", "police", "warrant", "jail")) else "urgent payment demand"
        amount_text = f" and {amount} request" if amount else ""
        return (
            f"{name}this looks like a fake {agency} message. The {detail}{amount_text} are classic impostor-scam tactics. "
            "Don't pay or share personal information. Contact the agency through its official .gov site."
        )

    if scam_type == "tech_support":
        company = _organization(result, "tech-support company")
        signs: list[str] = []
        if _has_any(message, ("virus", "hacked", "malware", "infected")):
            signs.append("the alarming virus warning")
        if "remote_access" in flags or _has_any(message, ("remote access", "anydesk", "teamviewer")):
            signs.append("the remote-access request")
        if "call_back_number" in flags or "call" in message.casefold():
            signs.append("the unsolicited callback number")
        warning = " and ".join(signs[:2]) if signs else "The unsolicited warning"
        return (
            f"{name}this looks like a fake {company} support alert. {warning[:1].upper() + warning[1:]} are common scam signs. "
            "Close the pop-up. Don't call, install software, or allow remote access."
        )

    if scam_type == "investment_crypto":
        promise = f"The guaranteed {percent} return" if percent else "The guaranteed-profit claim"
        payment = " and Bitcoin request" if _has_any(message, ("bitcoin", "crypto", "wallet")) else ""
        return (
            f"{name}this looks like an investment scam. {promise}{payment} are major warning signs; legitimate investments cannot guarantee profits. "
            "Don't send money or crypto. Independently verify the company first."
        )

    if scam_type == "romance":
        detail = f"The {amount} request" if amount else "The money request"
        story = "travel story" if _has_any(message, ("plane ticket", "flight", "overseas", "stranded")) else "emotional story"
        return (
            f"{name}this looks like a romance scam. {detail} tied to an urgent {story} is a common manipulation tactic. "
            "Don't send money, gift cards, crypto, or banking information. Talk with someone you trust."
        )

    if scam_type == "toll_payment":
        detail = f"The unexpected {amount} toll" if amount else "The unexpected toll demand"
        return (
            f"{name}this looks like a fake toll-payment text. {detail} and the payment link are common phishing signs. "
            "Don't tap the link. Check any balance only through your state's official toll website or app."
        )

    if scam_type == "prize_sweepstakes":
        prize = amount or "prize"
        return (
            f"{name}this looks like a prize scam. The claim that you won {prize} but must pay first is a major warning sign. "
            "Don't pay a fee or share financial information; legitimate prizes don't require upfront payment."
        )

    if scam_type == "employment":
        return (
            f"{name}this looks like a job scam. The unexpected offer and request for money, a check, or equipment are common warning signs. "
            "Don't deposit checks or pay fees. Verify the employer through its official website."
        )

    if scam_type == "marketplace":
        return (
            f"{name}this looks like a marketplace scam. The unusual payment or fee request is a common warning sign. "
            "Keep payment inside the platform and verify that funds actually cleared before sending anything."
        )

    red_flags = result.get("red_flags") or []
    reason = str(red_flags[0]).strip() if red_flags else "The message uses a common scam tactic."
    action = str(result.get("immediate_action", "")).strip()
    return f"{name}this message has scam warning signs. {reason} {action}".strip()


def _english_low_risk_body(result: dict) -> str:
    message = str(result.get("original_message") or "")
    name = _natural_name_prefix(result.get("first_name"))

    if _has_any(message, ("hang out", "dinner", "lunch", "coffee", "meet up", "meetup", "this week", "saturday", "sunday")):
        return (
            f"{name}this looks like a normal invitation to hang out. "
            "I don't see requests for money, passwords, codes, or urgent action. "
            "If you recognize the sender, it's probably safe to reply. "
            "If the number is unfamiliar, verify who it is first."
        )

    if _has_any(message, ("appointment", "reservation", "delivery window", "reply c", "confirm")):
        return (
            f"{name}this looks like a routine confirmation message. "
            "I don't see strong scam signs or a request for sensitive information. "
            "If you recognize the sender or organization, it's probably okay. "
            "Otherwise, verify through an official number before replying."
        )

    return (
        f"{name}I don't see strong scam signs in this message. "
        "There is no clear request for money, passwords, codes, or urgent action. "
        "If you recognize the sender and the message makes sense, it's probably safe to reply. "
        "If not, verify the number first."
    )


def _resource_block(resource: dict[str, str], locale: str) -> str:
    return (
        f"{RESOURCE_LABEL[locale]}: {resource['provider']} — {resource['title']}\n"
        f"{resource['url']}"
    )


def _finish_without_mid_sentence_cutoff(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    # This should be rare with the 600-character default. If a future template
    # grows unexpectedly, cut at the last sentence boundary rather than in the
    # middle of a word or instruction.
    candidate = text[:max_chars]
    boundary = max(candidate.rfind(". "), candidate.rfind("! "), candidate.rfind("? "), candidate.rfind("。"))
    if boundary >= 120:
        return candidate[: boundary + 1].rstrip()
    return candidate.rsplit(" ", 1)[0].rstrip(" ,;:") + "…"


def _with_resource(body: str, resource: dict[str, str] | None, locale: str, max_chars: int) -> str:
    if resource is None:
        return _finish_without_mid_sentence_cutoff(body, max_chars)

    block = _resource_block(resource, locale)
    combined = f"{body}\n{block}"
    if len(combined) <= max_chars:
        return combined

    # Always preserve the official URL. Shorten only the explanatory body if a
    # future response becomes unusually long.
    available = max_chars - len(block) - 1
    return f"{_finish_without_mid_sentence_cutoff(body, available)}\n{block}"


def _localized_reasoning(result: dict, locale: str, level: str) -> str:
    prefix = _prefix(result.get("first_name"), locale)
    status = RISK_LABELS[locale].get(level, RISK_LABELS[locale]["MEDIUM"])
    label = scam_label(str(result.get("scam_type", "unknown")), locale)
    assessment = ASSESSMENT[locale]["HIGH" if level == "HIGH" else "MEDIUM"].format(label=label)

    sections = result.get("response_sections") or {}
    why = str(sections.get("why") or "").strip()
    action = str(result.get("immediate_action") or sections.get("action") or "").strip()

    parts = [f"{prefix}{status}. {assessment}"]
    if why:
        parts.append(why)
    if action:
        parts.append(action)
    return " ".join(parts)


def format_sms_response(result: dict) -> str:
    locale = normalize_locale(result.get("language"))
    level = str(result.get("risk_level", "MEDIUM")).upper()
    max_chars = _max_chars(locale)

    if level == "LOW":
        if locale == "en" and result.get("original_message"):
            return _finish_without_mid_sentence_cutoff(_english_low_risk_body(result), max_chars)

        prefix = _prefix(result.get("first_name"), locale)
        status = RISK_LABELS[locale]["LOW"]
        sections = result.get("response_sections") or {}
        why = str(sections.get("why") or "").strip()
        action = str(result.get("immediate_action") or sections.get("action") or "").strip()
        detail = " ".join(part for part in (why, action) if part) or LOW_TEXT[locale]
        return _finish_without_mid_sentence_cutoff(f"{prefix}{status}. {detail}", max_chars)

    resource = _resource(result)

    if locale == "en" and result.get("original_message"):
        return _with_resource(_english_specific_body(result), resource, locale, max_chars)

    # Non-English replies now include the localized explanation generated by
    # GoldenGuard's deterministic response composer, followed by the localized
    # next step and the same category-specific trusted resource as English.
    return _with_resource(_localized_reasoning(result, locale, level), resource, locale, max_chars)
