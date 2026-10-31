import pytest

from src.detector import detect


CASES = [
    # Routine personal and service messages
    ("Hey man, are we still on for dinner at 7?", "LOW", "unknown"),
    ("Mom, I got home safely. Love you!", "LOW", "unknown"),
    ("Can you pick me up after practice?", "LOW", "unknown"),
    ("Happy birthday! I sent you a gift card in the mail.", "LOW", "unknown"),
    ("I need to buy gift cards for teacher appreciation day.", "LOW", "unknown"),
    ("The gift card code is printed on the back.", "LOW", "unknown"),
    ("I paid you back on Venmo for lunch.", "LOW", "unknown"),
    ("Here is the Zoom link for our class meeting https://zoom.us/j/12345", "LOW", "unknown"),
    ("Your dentist appointment is scheduled for Friday at 3 PM.", "LOW", "unknown"),
    ("Your prescription is ready for pickup.", "LOW", "unknown"),
    ("Your Amazon order has shipped. Track it in the Amazon app.", "LOW", "unknown"),
    ("UPS: Your package was delivered at 2:14 PM.", "LOW", "unknown"),
    ("Chase: Card ending 1234 was used at Target for $18.20. Open the Chase app if this was not you.", "LOW", "unknown"),
    ("Your code is 123456. Do not share this code with anyone.", "LOW", "unknown"),
    ("Reminder: rent is due tomorrow. Please pay through the tenant portal you normally use.", "LOW", "unknown"),
    ("I can pay you $20 for the concert ticket when I see you.", "LOW", "unknown"),
    ("The school meeting was moved to 4 PM.", "LOW", "unknown"),
    ("My financial adviser suggested a diversified index fund for retirement.", "LOW", "unknown"),
    ("Thanks for applying. Your interview is Tuesday at 10 AM on Zoom.", "LOW", "unknown"),
    ("Is the couch still available? I can pick it up Saturday and pay cash.", "LOW", "unknown"),
    ("Unknown number: Hi, is this Sarah?", "LOW", "unknown"),
    ("Can you call me when you get this?", "LOW", "unknown"),
    ("I bought bitcoin yesterday as a small investment.", "LOW", "unknown"),
    ("My grandson was arrested in the school play.", "LOW", "unknown"),
    ("Grandma is in the hospital but she is doing fine. No money needed.", "LOW", "unknown"),
    ("USPS says my package was delivered. I checked the official app.", "LOW", "unknown"),
    ("Your account is locked. Open the official Chase app to review it.", "LOW", "unknown"),
    ("IRS: your tax refund was deposited.", "LOW", "unknown"),
    ("Microsoft support will never ask for your password.", "LOW", "unknown"),
    ("You won the office raffle. No fee or payment is required.", "LOW", "unknown"),
    ("I overpaid you for lunch, I will just get it next time.", "LOW", "unknown"),
    ("I need a wire transfer receipt for my records.", "LOW", "unknown"),
    ("I love you. Send me $20 for pizza.", "LOW", "unknown"),

    # Cautionary but not yet a clear scam
    ("Hey mom, this is my new number. My old phone broke. Call me later.", "MEDIUM", "grandparent_emergency"),
    ("Your account needs attention. Call us.", "MEDIUM", "bank_impersonation"),

    # Bank and account impersonation
    ("Chase: Your account is locked. Verify now at http://chase-alert.xyz", "HIGH", "bank_impersonation"),
    ("Wells Fargo fraud department: call 888-555-1212 immediately or your account will close.", "HIGH", "bank_impersonation"),
    ("Bank of America: unusual activity detected. Reply with your account number to secure your account.", "HIGH", "bank_impersonation"),
    ("PayPal: your account has been limited. Sign in at http://paypal-resolution.top", "HIGH", "bank_impersonation"),
    ("Your debit card is suspended. Click this link to reactivate it: bit.ly/secure-now", "HIGH", "bank_impersonation"),
    ("Chase fraud alert. Call 888-555-1212 right away to prevent account closure.", "HIGH", "bank_impersonation"),
    ("Chase alert: verify your password at chase.com.security-check.xyz", "HIGH", "bank_impersonation"),

    # Package-delivery scams
    ("USPS: unable to deliver your parcel. Pay a 30 cent redelivery fee at http://usps-help.top", "HIGH", "package_delivery"),
    ("FedEx delivery failed. Update your address now at http://fedex-redelivery.xyz", "HIGH", "package_delivery"),
    ("UPS package on hold. Click to schedule redelivery: tinyurl.com/abc123", "HIGH", "package_delivery"),
    ("USPS delivery address incomplete. Update at usps.com.track-update.top.", "HIGH", "package_delivery"),

    # Family-emergency scams
    ("Grandma, I'm in jail and need $2,000 for bail. Please don't tell Mom. Send bitcoin.", "HIGH", "grandparent_emergency"),
    ("Hi Mom, my phone broke. This is my new number. I need money urgently for an emergency.", "HIGH", "grandparent_emergency"),
    ("Grandpa, I had an accident and my lawyer needs gift cards right away.", "HIGH", "grandparent_emergency"),
    ("Dad, I'm stranded and need $500 through Zelle. Please help me.", "HIGH", "grandparent_emergency"),
    ("I got arrested and need $800 for bail. Please help me and keep this between us.", "HIGH", "grandparent_emergency"),

    # Gift-card and business-impersonation requests
    ("Please buy four Apple gift cards and text me the codes.", "HIGH", "gift_card"),
    ("Your boss needs you to purchase Google Play cards immediately and send photos of the backs.", "HIGH", "gift_card"),
    ("This is your CEO. Purchase $1,000 in Apple cards and send photos of the codes.", "HIGH", "gift_card"),

    # Government impersonation
    ("Pay the IRS with gift cards to avoid arrest.", "HIGH", "government_impersonation"),
    ("Social Security Administration: your benefits will be suspended unless you call now and verify your SSN.", "HIGH", "government_impersonation"),
    ("IRS final warning: pay $600 today through Bitcoin or a warrant will be issued.", "HIGH", "government_impersonation"),
    ("Medicare needs your card number to issue a new benefits card. Reply immediately.", "HIGH", "government_impersonation"),

    # Tech support
    ("Microsoft support detected a virus. Call 800-555-9999 now.", "HIGH", "tech_support"),
    ("Install AnyDesk so our technician can fix your compromised computer.", "HIGH", "tech_support"),
    ("Apple security warning: your iPhone is hacked. Tap here to remove malware http://apple-help.xyz", "HIGH", "tech_support"),
    ("Amazon refund team: install AnyDesk so we can return your money.", "HIGH", "tech_support"),

    # Romance scams
    ("My love, I need $1,500 for a plane ticket so I can finally visit you. Send Bitcoin.", "HIGH", "romance"),
    ("I am stationed overseas and my bank account is frozen. Can you wire me money?", "HIGH", "romance"),
    ("I am a soldier overseas and need money for a flight home, sweetheart.", "HIGH", "romance"),

    # Investments and cryptocurrency
    ("Guaranteed 40% profit with zero risk. Deposit crypto today.", "HIGH", "investment_crypto"),
    ("Join this trading platform and double your money in one week.", "HIGH", "investment_crypto"),
    ("Kindly remit 0.5 BTC to release your investment profit.", "HIGH", "investment_crypto"),
    ("Deposit $500 into this crypto platform and earn guaranteed daily profits.", "HIGH", "investment_crypto"),

    # Prize scams
    ("Congratulations, you won $10,000! Pay a $100 processing fee to claim.", "HIGH", "prize_sweepstakes"),
    ("You have been selected as a lottery winner. Send your bank information to receive funds.", "HIGH", "prize_sweepstakes"),
    ("You won a free car. Send your SSN and pay delivery taxes to claim it.", "HIGH", "prize_sweepstakes"),

    # Employment scams
    ("We are hiring a remote assistant. Deposit this check and buy equipment from our vendor.", "HIGH", "employment"),
    ("Job offer: pay a $75 training fee before your first day.", "HIGH", "employment"),
    ("Remote job: we will mail a check. Deposit it and send the remaining funds to our vendor.", "HIGH", "employment"),

    # Marketplace scams
    ("I overpaid for the sofa. Please refund the difference through Zelle.", "HIGH", "marketplace"),
    ("Marketplace buyer: I will send a courier. Please pay the insurance fee first.", "HIGH", "marketplace"),
    ("Buyer says payment is pending. Pay a $75 insurance fee to release it.", "HIGH", "marketplace"),

    # Toll scams
    ("Illinois Tollway: unpaid toll of $6.99. Pay now at http://illinois-tolls.top", "HIGH", "toll_payment"),
    ("Final notice: outstanding EZPass balance. Click to avoid penalties.", "HIGH", "toll_payment"),
    ("Unpaid toll notice. Pay $4.90 at ezpass-payment.click today.", "HIGH", "toll_payment"),

    # Account takeover
    ("Send me the verification code that just came to your phone.", "HIGH", "account_takeover"),
    ("What is the six digit code you received? I need it to verify your account.", "HIGH", "account_takeover"),
    ("Your bank security code is 123456. Tell me the code to cancel the transfer.", "HIGH", "account_takeover"),
]


@pytest.mark.parametrize(("message", "expected_level", "expected_type"), CASES)
def test_accuracy_matrix(message, expected_level, expected_type):
    result = detect(message, "Alex")
    assert result["risk_level"] == expected_level, result
    assert result["scam_type"] == expected_type, result


def test_low_risk_messages_have_no_scam_links():
    for message, expected_level, _ in CASES:
        if expected_level != "LOW":
            continue
        result = detect(message, "Alex")
        assert result["helpful_resources"] == [], result
        assert "Helpful resources:" not in result["personalized_response"]


def test_high_risk_messages_explain_and_link():
    for message, expected_level, _ in CASES:
        if expected_level != "HIGH":
            continue
        result = detect(message, "Alex")
        assert result["red_flags"], result
        assert result["helpful_resources"], result
        assert "What to do now:" in result["personalized_response"]
        assert "Helpful resources:" in result["personalized_response"]
