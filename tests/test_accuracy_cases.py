import pytest

from src.detector import detect


@pytest.mark.parametrize(
    ("message", "expected_level", "expected_type"),
    [
        ("hey bro u wanna hang out on saturday? dinners on me", "LOW", "unknown"),
        ("Reminder: your dentist appointment is tomorrow at 2 PM. Reply C to confirm.", "LOW", "unknown"),
        ("Your prescription is ready for pickup at the pharmacy.", "LOW", "unknown"),
        ("Your verification code is 438221. Do not share it with anyone.", "LOW", "unknown"),
        ("UPS: your package was delivered at the front door.", "LOW", "unknown"),
        ("I bought you an Apple gift card for your birthday.", "LOW", "unknown"),
        ("Chase alert: Card ending 1234 was used for $18.20 at Target. Open the Chase app if this was not you.", "LOW", "unknown"),
        ("Can you send me the verification code that just came to your phone?", "HIGH", "account_takeover"),
        ("Your Chase account is suspended. Verify now at http://chase-security-alert.xyz", "HIGH", "bank_impersonation"),
        ("USPS: package cannot be delivered. Pay $0.30 at http://usps-redelivery.top", "HIGH", "package_delivery"),
        ("Grandma, I was arrested and need $500 for bail. Send bitcoin and don't tell mom.", "HIGH", "grandparent_emergency"),
        ("Hi mom, I lost my phone. This is my new number. I need money urgently.", "HIGH", "grandparent_emergency"),
        ("Please buy two Apple gift cards and send me the codes.", "HIGH", "gift_card"),
        ("The IRS has issued an arrest warrant. Pay with gift cards today to avoid arrest.", "HIGH", "government_impersonation"),
        ("Microsoft detected a virus. Call support now at 800-555-1234", "HIGH", "tech_support"),
        ("Install AnyDesk so I can remove the virus from your computer.", "HIGH", "tech_support"),
        ("I love you. I need $2,000 for a plane ticket to visit you. Send bitcoin.", "HIGH", "romance"),
        ("Guaranteed 30% return. Deposit bitcoin today on our trading platform.", "HIGH", "investment_crypto"),
        ("Congratulations! You won $5,000. Pay a $50 processing fee to claim your prize.", "HIGH", "prize_sweepstakes"),
    ],
)
def test_expected_risk_and_category(message, expected_level, expected_type):
    result = detect(message, "Test")
    assert result["risk_level"] == expected_level, result
    assert result["scam_type"] == expected_type, result


def test_low_risk_messages_do_not_show_scam_links():
    result = detect("hey bro u wanna hang out on saturday? dinners on me", "Bob")
    assert result["helpful_resources"] == []
    assert "probably okay" in result["personalized_response"]
    assert "Helpful resources" not in result["personalized_response"]


def test_grandparent_scam_gets_specific_action_and_resources():
    result = detect(
        "Grandma, I was arrested and need $500 for bail. Send bitcoin and don't tell mom.",
        "Margaret",
    )
    assert result["risk_score"] >= 90
    assert "Call the relative" in result["personalized_response"]
    assert any(resource["provider"] == "FTC" for resource in result["helpful_resources"])


def test_verification_code_notice_is_not_confused_with_code_request():
    notice = detect("Your verification code is 123456. Do not share it with anyone.", "Alex")
    request = detect("Please send me the verification code you received.", "Alex")
    assert notice["risk_level"] == "LOW"
    assert request["risk_level"] == "HIGH"
