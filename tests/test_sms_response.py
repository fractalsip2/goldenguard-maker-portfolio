from src.sms_gateway import format_sms_response
from src.sms_response import SUPPORTED_RESOURCE_CATEGORIES


def test_english_high_risk_keeps_personalization_and_complete_action():
    result = {
        "first_name": "DJ",
        "language": "en",
        "risk_level": "HIGH",
        "scam_type": "bank_impersonation",
        "organization": "Chase",
        "original_message": "Chase says my account is locked and I need to confirm my password immediately.",
        "signal_flags": ["credential_request", "urgency"],
        "immediate_action": "Do not click the link, reply, or share account details.",
        "helpful_resources": [],
    }
    message = format_sms_response(result)
    assert message.startswith("DJ, this looks like a fake Chase alert")
    assert "locked-account claim" in message
    assert "official app" in message
    assert "Bank Impersonation Scams" in message
    assert "online-banking-fraud" in message
    assert not message.endswith("…")
    assert len(message) <= 600


def test_package_reply_no_longer_cuts_off_to_fit_two_segments():
    result = {
        "first_name": "DJ",
        "language": "en",
        "risk_level": "MEDIUM",
        "scam_type": "package_delivery",
        "organization": "USPS",
        "original_message": "USPS says my package is delayed. I need to pay a $2.99 redelivery fee at this link.",
        "signal_flags": ["money_request", "organization_impersonation"],
        "urls_found": [],
        "immediate_action": "Do not use the message's link.",
        "helpful_resources": [],
    }
    message = format_sms_response(result)
    assert message.startswith("DJ, this looks like a fake USPS redelivery text")
    assert "$2.99 fee" in message
    assert "payment link" in message
    assert "Check the package only in the USPS app or at usps.com." in message
    assert "Learn More: USPIS — USPS Package-Tracking Text Scams" in message
    assert "https://www.uspis.gov/news/scam-article/smishing-package-tracking-text-scams" in message
    assert len(message) > 306  # proves the obsolete two-segment cap is gone
    assert len(message) <= 600


def test_low_risk_social_message_is_natural_and_message_specific():
    result = {
        "first_name": "DJ",
        "language": "en",
        "risk_level": "LOW",
        "scam_type": "unknown",
        "original_message": "Yo bro lets hang out sometime this week dinner's on me",
        "immediate_action": "",
        "helpful_resources": [],
    }
    message = format_sms_response(result)
    assert message.startswith("DJ, this looks like a normal invitation to hang out")
    assert "money, passwords, codes, or urgent action" in message
    assert "GoldenGuard: LOW RISK" not in message
    assert not message.endswith("…")


def test_unknown_submitted_url_is_never_repeated():
    result = {
        "first_name": "DJ",
        "language": "en",
        "risk_level": "HIGH",
        "scam_type": "bank_impersonation",
        "organization": "Chase",
        "original_message": "Your Chase account is locked. Verify at https://evil.example",
        "signal_flags": ["url", "credential_request"],
        "immediate_action": "Do not use the message's link. Verify through your bank's official app.",
        "helpful_resources": [],
        "urls_found": ["https://evil.example"],
    }
    message = format_sms_response(result)
    assert "evil.example" not in message


def test_existing_non_english_reply_includes_reasoning_guidance_and_link():
    result = {
        "first_name": "María",
        "language": "es",
        "risk_level": "HIGH",
        "scam_type": "bank_impersonation",
        "immediate_action": "No use el enlace. Abra la aplicación oficial de su banco.",
        "response_sections": {
            "why": "Por qué GoldenGuard lo marcó: le pide información confidencial de la cuenta.",
            "action": "No use el enlace. Abra la aplicación oficial de su banco.",
        },
        "helpful_resources": [],
    }
    message = format_sms_response(result)
    assert message.startswith("María, RIESGO ALTO")
    assert "Por qué GoldenGuard lo marcó" in message
    assert "aplicación oficial" in message
    assert "Más información: AARP" in message
    assert "online-banking-fraud" in message


def test_expanded_japanese_reply_has_full_safety_structure():
    result = {
        "first_name": "Ken",
        "language": "ja",
        "risk_level": "HIGH",
        "scam_type": "government_impersonation",
        "signal_flags": ["threat", "money_request"],
        "original_message": "IRS says I will be arrested unless I pay now.",
        "helpful_resources": [],
    }
    message = format_sms_response(result)
    assert "高リスク" in message
    assert "政府機関なりすまし詐欺" in message
    assert "理由：" in message
    assert "対処：" in message
    assert "詳しく見る: FTC" in message
    assert "how-avoid-government-impersonation-scam" in message


def test_every_supported_category_has_a_specific_official_resource():
    cases = {
        "bank_impersonation": "online-banking-fraud",
        "account_takeover": "how-recognize-avoid-phishing-scams",
        "gift_card": "avoiding-and-reporting-gift-card-scams",
        "government_impersonation": "how-avoid-government-impersonation-scam",
        "romance": "what-know-about-romance-scams",
        "tech_support": "how-spot-avoid-and-report-tech-support-scams",
        "prize_sweepstakes": "fake-prize-sweepstakes-and-lottery-scams",
        "employment": "job-scams",
        "marketplace": "selling-stuff-online",
        "toll_payment": "got-text-about-unpaid-tolls",
        "unknown": "consumer.ftc.gov/scams",
    }

    assert set(cases) | {
        "grandparent_emergency",
        "package_delivery",
        "investment_crypto",
    } == SUPPORTED_RESOURCE_CATEGORIES

    for scam_type, url_fragment in cases.items():
        result = {
            "first_name": "DJ",
            "language": "en",
            "risk_level": "HIGH",
            "scam_type": scam_type,
            "original_message": "Unexpected message asking me to act immediately and send money.",
            "signal_flags": ["urgency", "money_request"],
            "immediate_action": "Do not send money. Verify independently.",
            "helpful_resources": [],
        }
        message = format_sms_response(result)
        assert url_fragment in message, scam_type
        assert "Learn More:" in message, scam_type
        assert len(message) <= 600, scam_type
