"""GoldenGuard's end-to-end scam analysis pipeline."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import joblib

from src.config import MODEL_PATH
from src.knowledge import get_helpful_resources
from src.localization import localized_action, normalize_locale
from src.response import compose_response
from src.rules import analyze_rules
from src.scam_types import classify_scam_type


@lru_cache(maxsize=1)
def load_model() -> Any:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "No trained model was found. Run: python -m src.trainer"
        )
    return joblib.load(MODEL_PATH)


def clamp_score(value: float) -> int:
    return max(0, min(100, round(value)))


def risk_level(score: int) -> str:
    if score >= 75:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def verdict_for(level: str) -> str:
    return {
        "HIGH": "likely_scam",
        "MEDIUM": "suspicious",
        "LOW": "lower_risk",
    }[level]


def _category_with(category: dict, scam_type: str) -> dict:
    all_scores = category.get("all_category_scores", {})
    return {
        **category,
        "scam_type": scam_type,
        "category_score": max(
            category.get("category_score", 0),
            all_scores.get(scam_type, 0),
        ),
    }


def resolve_category(text: str, category: dict, rules: dict) -> dict:
    """Resolve ambiguous category matches using concrete rule context."""

    lowered = text.lower()
    flags = set(rules["signal_flags"])
    all_scores = category.get("all_category_scores", {})
    organizations = set(rules["organizations"])

    # A message asking for a code is account takeover regardless of branding.
    if rules["code_request"]:
        return _category_with(category, "account_takeover")

    # Informational code notices are not account-takeover requests.
    if rules["safe_code_notice"] and not rules["code_request"]:
        return {
            **category,
            "scam_type": "unknown",
            "matched_signals": [],
            "category_score": 0,
        }

    # Government branding should dominate a generic gift-card/payment match.
    government_orgs = {
        "IRS", "Social Security Administration", "Medicare"
    }
    if organizations.intersection(government_orgs) and flags.intersection({
        "threat", "credential_request", "money_request", "risky_payment",
        "urgency", "organization_impersonation",
    }):
        return _category_with(category, "government_impersonation")

    # Family + emergency/new number + money is a family-emergency scam.
    if rules["family_reference"] and flags.intersection({"emergency", "new_number"}) and flags.intersection({
        "money_request", "risky_payment", "secrecy", "urgency"
    }):
        return _category_with(category, "grandparent_emergency")

    if "new_number" in flags and flags.intersection({"money_request", "risky_payment"}) and re_contains_family_address(lowered):
        return _category_with(category, "grandparent_emergency")

    # Security warnings, remote-access requests, and fake support calls.
    if flags.intersection({"remote_access", "security_alert"}) and (
        organizations.intersection({"Apple", "Microsoft"})
        or "support" in lowered
        or "technician" in lowered
        or "computer" in lowered
        or "iphone" in lowered
    ):
        return _category_with(category, "tech_support")

    # Named delivery carriers plus delivery language should stay package-specific.
    if organizations.intersection({"USPS", "UPS", "FedEx"}) and (
        all_scores.get("package_delivery", 0) >= 5
        or any(term in lowered for term in ("package", "parcel", "delivery", "redelivery", "tracking"))
    ):
        return _category_with(category, "package_delivery")

    # Named financial services or explicit card/account warnings.
    if organizations.intersection({"Chase", "Wells Fargo", "Bank of America", "Citibank", "PayPal"}) and flags.intersection({
        "domain_mismatch", "suspicious_tld", "shortened_url", "credential_request",
        "urgency", "vague_account_alert", "call_back_number", "url",
    }):
        return _category_with(category, "bank_impersonation")

    if all_scores.get("bank_impersonation", 0) >= 4 and flags.intersection({
        "url", "urgency", "credential_request", "vague_account_alert", "call_back_number"
    }):
        return _category_with(category, "bank_impersonation")

    if rules["romance_money_context"]:
        return _category_with(category, "romance")

    if rules["investment_promise"] or (
        "risky_payment" in flags
        and any(term in lowered for term in ("investment", "invest", "trading", "profit", "return"))
    ):
        return _category_with(category, "investment_crypto")

    if rules["employment_fee"] or (
        all_scores.get("employment", 0) >= 4
        and flags.intersection({"money_request", "fake_check", "risky_payment"})
    ):
        return _category_with(category, "employment")

    if rules["marketplace_fee"] or (
        all_scores.get("marketplace", 0) >= 3
        and flags.intersection({"money_request", "overpayment", "fake_check", "risky_payment"})
    ):
        return _category_with(category, "marketplace")

    if "toll_demand" in flags:
        return _category_with(category, "toll_payment")

    if "gift_card_request" in flags:
        return _category_with(category, "gift_card")

    # Strong prize language paired with a fee or personal-data request.
    if all_scores.get("prize_sweepstakes", 0) >= 5 and flags.intersection({
        "money_request", "credential_request", "risky_payment", "prize"
    }):
        return _category_with(category, "prize_sweepstakes")

    # A weak category word in an otherwise normal message should not label the
    # conversation as a scam category.
    if rules["is_clear_benign"] and not flags.intersection({
        "money_request", "risky_payment", "credential_request", "code_request",
        "domain_mismatch", "shortened_url", "suspicious_tld", "threat",
        "emergency", "security_alert", "remote_access", "prize",
    }):
        return {
            **category,
            "scam_type": "unknown",
            "matched_signals": [],
            "category_score": 0,
        }

    return category


def re_contains_family_address(lowered: str) -> bool:
    return any(
        lowered.startswith(prefix)
        or f" {prefix}" in lowered
        for prefix in (
            "hi mom", "hey mom", "mom,", "hi dad", "hey dad", "dad,",
            "grandma,", "grandpa,", "mother,", "father,"
        )
    )


def _scenario_floor(scam_type: str, rules: dict, category: dict) -> int:
    flags = set(rules["signal_flags"])
    category_score = category.get("category_score", 0)
    money = bool(flags.intersection({"money_request", "risky_payment"})) or rules["money_request"]

    if rules["safe_code_notice"] and not rules["code_request"]:
        return 0

    if rules["code_request"]:
        return 95

    if scam_type == "grandparent_emergency":
        if money and flags.intersection({"emergency", "new_number", "secrecy"}):
            return 94
        if "new_number" in flags and rules.get("family_reference"):
            return 48

    if money and "new_number" in flags and flags.intersection({"urgency", "emergency"}):
        return 92

    if money and "emergency" in flags and category_score >= 3:
        return 90

    if scam_type == "gift_card" and flags.intersection({"gift_card_request", "risky_payment"}):
        return 94

    if scam_type == "government_impersonation" and flags.intersection({
        "threat", "money_request", "risky_payment", "credential_request", "code_request"
    }):
        return 94

    if scam_type == "bank_impersonation":
        if flags.intersection({"domain_mismatch", "suspicious_tld", "credential_request", "code_request"}):
            return 94
        if "shortened_url" in flags and flags.intersection({"url", "urgency"}):
            return 88
        if {"url", "urgency"}.issubset(flags):
            return 86
        if "call_back_number" in flags and flags.intersection({"urgency", "vague_account_alert"}):
            return 82
        if "vague_account_alert" in flags:
            return 48

    if scam_type == "package_delivery":
        if flags.intersection({"domain_mismatch", "suspicious_tld", "shortened_url"}) and flags.intersection({"url", "money_request", "credential_request"}):
            return 92
        if "shortened_url" in flags and "url" in flags:
            return 84

    if scam_type == "tech_support" and flags.intersection({"remote_access", "call_back_number", "security_alert"}):
        return 92

    if scam_type == "romance" and flags.intersection({"romance_money", "money_request", "risky_payment"}):
        return 90

    if scam_type == "investment_crypto":
        if flags.intersection({"investment_promise", "money_request", "risky_payment"}):
            return 90
        if category_score >= 8:
            return 84

    if scam_type == "prize_sweepstakes":
        if flags.intersection({"money_request", "credential_request", "risky_payment"}):
            return 90
        if "prize" in flags:
            return 70

    if scam_type == "employment":
        if flags.intersection({"fake_check", "employment_fee", "risky_payment"}):
            return 92
        if "money_request" in flags:
            return 84

    if scam_type == "marketplace":
        if flags.intersection({"overpayment", "fake_check", "marketplace_fee"}):
            return 92
        if "money_request" in flags:
            return 82

    if scam_type == "toll_payment" and flags.intersection({"url", "money_request", "toll_demand"}):
        return 90

    if "domain_mismatch" in flags and flags.intersection({"url", "urgency", "credential_request", "money_request"}):
        return 88

    if "suspicious_tld" in flags and flags.intersection({"credential_request", "money_request", "urgency"}):
        return 84

    return 0


def calculate_risk_score(
    model_probability: float,
    rules: dict,
    category: dict,
) -> tuple[int, dict]:
    """Combine the statistical model with explicit signals conservatively."""

    scam_type = category["scam_type"]
    category_score = category.get("category_score", 0)
    model_points = model_probability * 15.0
    category_points = min(category_score * 1.8, 18.0)
    rule_points = float(rules["risk_points"])

    if rules["safe_code_notice"] and not rules["code_request"]:
        score = min(model_probability * 100 * 0.12, 15)
        return clamp_score(score), {
            "model_points": round(score, 1),
            "rule_points": 0,
            "category_points": 0,
            "scenario_floor": 0,
        }

    flags = set(rules["signal_flags"])
    dangerous_flags = flags.intersection({
        "domain_mismatch", "shortened_url", "suspicious_tld", "threat",
        "code_request", "credential_request", "money_request", "risky_payment",
        "secrecy", "emergency", "fake_check", "overpayment", "remote_access",
        "security_alert", "prize", "employment_fee", "marketplace_fee",
        "toll_demand", "romance_money", "investment_promise", "vague_account_alert",
    })

    if not dangerous_flags and rules["is_clear_benign"]:
        score = model_probability * 100 * 0.10
        return clamp_score(min(score, 12)), {
            "model_points": round(min(score, 12), 1),
            "rule_points": 0,
            "category_points": 0,
            "scenario_floor": 0,
        }

    if not dangerous_flags and scam_type == "unknown":
        multiplier = 0.12 if rules["is_routine"] else 0.18
        score = model_probability * 100 * multiplier
        return clamp_score(min(score, 24)), {
            "model_points": round(min(score, 24), 1),
            "rule_points": 0,
            "category_points": 0,
            "scenario_floor": 0,
        }

    score = model_points + rule_points + category_points
    floor = _scenario_floor(scam_type, rules, category)
    score = max(score, floor)

    # A single weak signal should prompt caution, not a high-risk verdict.
    if len(dangerous_flags) == 1 and not floor and rule_points <= 20:
        score = min(score, 58)

    return clamp_score(score), {
        "model_points": round(model_points, 1),
        "rule_points": round(rule_points, 1),
        "category_points": round(category_points, 1),
        "scenario_floor": floor,
    }


def action_for(level: str, scam_type: str, rules: dict) -> str:
    if level == "LOW":
        if rules["safe_code_notice"] and not rules["code_request"]:
            return (
                "Keep the code private. If you requested it, no action is needed. If you did not request it, open the official app or website and secure the account."
            )
        if not rules["evidence"] or rules["is_routine"]:
            return (
                "If this came from a number you recognize and the message makes sense in context, it is probably okay. "
                "If the number is unfamiliar, confirm who sent it before replying, sharing information, or meeting."
            )
        return (
            "GoldenGuard did not find enough evidence to call this a scam. Verify the sender through a number or account you already trust before taking any unusual action."
        )

    actions = {
        "bank_impersonation": (
            "Do not click the link, reply, call the number in the message, or share account details. Open your bank's official app or call the number printed on the back of your card."
        ),
        "account_takeover": (
            "Do not share the verification code, password, or account information. Open the official app or website directly and change the password if you think someone is trying to access the account."
        ),
        "gift_card": (
            "Do not buy or send gift cards, and never share the card number, PIN, or a photo of the card. Verify the request by contacting the person or organization through a number you already trust."
        ),
        "grandparent_emergency": (
            "Do not send money yet. Call the relative or another family member using a phone number you already know. Ignore any request to keep the situation secret."
        ),
        "government_impersonation": (
            "Do not send money or reveal personal information. Look up the agency's official .gov website and contact it through a verified number."
        ),
        "package_delivery": (
            "Do not use the link in the message. Open the carrier's official app or type its official website address yourself to check the package."
        ),
        "romance": (
            "Do not send money, gift cards, cryptocurrency, or banking information. Pause contact and discuss the situation with someone you trust."
        ),
        "investment_crypto": (
            "Do not deposit money or cryptocurrency. Independently research the company and remember that legitimate investments cannot guarantee profits."
        ),
        "tech_support": (
            "Do not call the number in the warning, install software, or allow remote access. Contact the company through its official website or built-in support application."
        ),
        "prize_sweepstakes": (
            "Do not pay a fee or provide financial information to claim the prize. A legitimate prize does not require an upfront payment."
        ),
        "employment": (
            "Do not deposit the check, pay an upfront fee, buy equipment, or send money back. Verify the employer through its official website and independently found contact information."
        ),
        "marketplace": (
            "Do not pay an insurance or courier fee, refund an overpayment, or move payment outside the marketplace. Verify that any payment actually cleared in the official platform."
        ),
        "toll_payment": (
            "Do not use the link in the text. Look up your state's official tolling agency yourself and check for any balance through its verified website or phone number."
        ),
    }

    return actions.get(
        scam_type,
        "Do not click links, send money, or share personal information. Verify the request through a separate channel you already trust.",
    )


def detect(
    message: str,
    first_name: str | None = None,
    preferred_language: str | None = None,
) -> dict:
    text = message.strip()
    if not text:
        raise ValueError("Message text cannot be empty.")
    if len(text) > 10000:
        raise ValueError("Message text is too long.")

    model = load_model()
    model_probability = float(model.predict_proba([text])[0][1])

    rules = analyze_rules(text)
    category = resolve_category(text, classify_scam_type(text), rules)

    score, score_breakdown = calculate_risk_score(model_probability, rules, category)
    level = risk_level(score)

    # Avoid returning a misleading category for normal messages that only happen
    # to contain words such as "love," "gift card," "package," or "buyer."
    if level == "LOW" and rules["is_clear_benign"]:
        category = {
            **category,
            "scam_type": "unknown",
            "matched_signals": [],
            "category_score": 0,
        }

    scam_type = category["scam_type"]
    locale = normalize_locale(preferred_language)
    action = localized_action(
        locale=locale,
        risk_level=level,
        scam_type=scam_type,
        is_routine=rules["is_routine"],
        safe_code_notice=rules["safe_code_notice"] and not rules["code_request"],
        has_evidence=bool(rules["evidence"]),
    )

    resources = []
    if level in {"MEDIUM", "HIGH"}:
        resources = get_helpful_resources(text, scam_type, top_k=2)

    evidence = list(rules["evidence"])
    if category["matched_signals"] and level in {"MEDIUM", "HIGH"} and not evidence:
        evidence.append(
            "The wording matches a common "
            + scam_type.replace("_", " ")
            + " pattern."
        )

    organization = rules["organizations"][0] if rules["organizations"] else None
    response = compose_response(
        first_name=first_name,
        risk_level=level,
        risk_score=score,
        scam_type=scam_type,
        evidence=evidence,
        action=action,
        resources=resources,
        organization=organization,
        seed_text=text,
        is_routine=rules["is_routine"],
        safe_code_notice=rules["safe_code_notice"] and not rules["code_request"],
        preferred_language=locale,
        signal_flags=rules["signal_flags"],
    )

    return {
        "first_name": first_name,
        "language": locale,
        "verdict": verdict_for(level),
        "risk_level": level,
        "risk_score": score,
        "scam_probability": score,
        "model_probability": round(model_probability * 100),
        "score_breakdown": score_breakdown,
        "category_boost": round(score_breakdown["category_points"]),
        "scam_type": scam_type,
        "organization": organization,
        "matched_signals": category["matched_signals"],
        "red_flags": evidence,
        "signal_flags": rules["signal_flags"],
        "urls_found": rules["urls"],
        "domains_found": rules["domains"],
        "immediate_action": action,
        "helpful_resources": resources,
        "response_sections": {
            "headline": response["headline"],
            "opening": response["opening"],
            "why": response["why"],
            "action": response["action"],
            "resources": response["resources"],
        },
        "personalized_response": response["full_text"],
    }
