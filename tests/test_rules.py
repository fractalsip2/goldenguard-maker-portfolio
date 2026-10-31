from src.rules import analyze_rules
from src.scam_types import classify_scam_type


def test_bank_scam_signals():
    text = (
        "Your Chase account is suspended. Verify immediately at "
        "http://secure-login.xyz"
    )
    rules = analyze_rules(text)
    category = classify_scam_type(text)

    assert rules["rule_boost"] > 0
    assert rules["urls"]
    assert category["scam_type"] == "bank_impersonation"


def test_safe_message_has_no_forced_category():
    category = classify_scam_type(
        "Your prescription is ready for pickup at the pharmacy."
    )
    assert category["scam_type"] == "unknown"
