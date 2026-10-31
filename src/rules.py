"""Explainable deterministic fraud signals for GoldenGuard.

The statistical model is useful for broad language patterns, but these rules
identify concrete warning signs and benign context. The detector combines both
instead of allowing a single keyword to decide the result.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


URGENCY_TERMS = [
    "urgent", "urgently", "immediately", "act now", "limited time",
    "within 24 hours", "final warning", "locked", "suspended", "restricted",
    "expires today", "last chance", "today only", "right away",
    "as soon as possible", "avoid penalties", "before it is too late",
]

THREAT_TERMS = [
    "avoid arrest", "arrest warrant", "legal action", "police will",
    "account will be closed", "benefits will be suspended",
    "service will be disconnected", "warrant for your arrest",
    "your ssn will be suspended", "prosecution", "fine will increase",
]

CREDENTIAL_TERMS = [
    "password", "account number", "routing number", "social security number",
    "ssn", "security code", "card number", "login information",
    "banking information", "date of birth", "mother's maiden name",
]

CODE_REQUEST_PATTERNS = [
    r"\b(?:send|share|tell|give|forward|text|reply with|read me|provide)\b.{0,45}\b(?:verification|one[- ]?time|security|six[- ]?digit)?\s*(?:code|otp|passcode)\b",
    r"\bwhat(?:'s| is)\b.{0,35}\b(?:code|otp|passcode)\b",
    r"\bwhat\b.{0,25}\b(?:six[- ]?digit|verification|security)\b.{0,15}\b(?:number|code)\b",
    r"\benter\b.{0,30}\b(?:verification|one[- ]?time|security)?\s*(?:code|otp|passcode)\b.{0,45}\b(?:link|site|page|form)\b",
]

SAFE_CODE_NOTICE_PATTERNS = [
    r"\bdo not share\b.{0,55}\b(?:code|otp|passcode)\b",
    r"\bnever share\b.{0,55}\b(?:code|otp|passcode)\b",
    r"\byour (?:verification|one[- ]?time|security)?\s*(?:code|otp|passcode) is\b",
    r"\b(?:code|otp|passcode)\b.{0,30}\bexpires in\b",
]

RISKY_PAYMENT_TERMS = [
    "gift card", "gift cards", "apple gift card", "apple gift cards",
    "google play card", "google play cards", "steam card", "steam cards",
    "wire transfer", "western union", "moneygram", "bitcoin",
    "cryptocurrency", "crypto", "btc", "zelle", "venmo", "cash app",
]

MONEY_REQUEST_PATTERNS = [
    r"\b(?:send|wire|transfer|pay|deposit|buy|purchase|refund|reimburse|return|remit)\b.{0,55}(?:\$\s?\d|money|funds|payment|fee|bitcoin|btc|crypto|gift cards?|zelle|venmo|cash app)",
    r"\b(?:need|needs|owe|require|requires|required)\b.{0,45}(?:\$\s?\d|money|payment|fee|funds|deposit|gift cards?|bitcoin|btc|crypto|zelle|venmo|cash app)",
    r"\b(?:payment|fee|balance|charge)\b.{0,40}(?:due|required|needed|now|today|first|before)",
    r"\bpay\b.{0,25}\b(?:insurance|training|processing|release|redelivery|activation)\s+fee\b",
]

SECRECY_TERMS = [
    "don't tell anyone", "do not tell anyone", "keep this secret", "between us",
    "don't tell mom", "don't tell dad", "do not contact anyone",
    "please keep this confidential", "don't call my parents",
]

EMERGENCY_TERMS = [
    "arrested", "in jail", "bail", "hospital", "accident", "stranded",
    "emergency", "lawyer", "police station", "kidnapped", "mugged",
    "passport stolen", "medical emergency",
]

FAMILY_REFERENCE_TERMS = [
    "grandma", "grandpa", "grandmother", "grandfather", "mom", "dad",
    "mother", "father", "son", "daughter", "grandson", "granddaughter",
    "aunt", "uncle", "niece", "nephew",
]

NEW_NUMBER_TERMS = [
    "new number", "lost my phone", "phone broke", "using a friend's phone",
    "temporary number", "new phone number", "old phone stopped working",
]

REMOTE_ACCESS_TERMS = [
    "remote access", "anydesk", "teamviewer", "screen share", "install this app",
    "let me access your computer", "connect to your computer", "remote desktop",
    "supremo", "ultraviewer",
]

SECURITY_ALERT_TERMS = [
    "virus detected", "computer infected", "device infected", "security warning",
    "malware detected", "hacked", "compromised computer", "iphone is hacked",
]

PRIZE_TERMS = [
    "you won", "you've won", "you have won", "selected as a winner",
    "claim your prize", "lottery winner", "sweepstakes", "cash prize",
]

ACTION_TERMS = [
    "click", "tap", "open the link", "visit", "verify", "confirm", "update",
    "sign in", "login", "log in", "call now", "call us", "reply",
    "reactivate", "resolve", "complete the form", "follow the link",
]

ROUTINE_PATTERNS = [
    r"\b(?:hang out|dinner|lunch|breakfast|movie|meet up|meet at|see you|pick you up|come over)\b",
    r"\b(?:appointment|dentist|doctor|pharmacy|prescription)\b.{0,80}\b(?:tomorrow|today|ready|scheduled|confirm|pickup|pick up)\b",
    r"\b(?:class|school|practice|rehearsal|meeting|interview)\b.{0,80}\b(?:tomorrow|today|tuesday|wednesday|thursday|friday|cancelled|canceled|starts|scheduled|zoom)\b",
    r"\b(?:happy birthday|congratulations on|thank you|thanks for|love you|got home safely)\b",
    r"\b(?:still on for|are we still|what time|see you at|pick it up saturday|pay cash)\b",
    r"\b(?:delivered|shipped|ready for pickup|ready for pick up)\b",
]

SAFE_CONTEXT_PATTERNS = [
    r"\b(?:open|check|review) (?:the|your) official (?:app|website)\b",
    r"\bopen the (?:official )?(?:chase|wells fargo|bank of america|citi|paypal|amazon|ups|fedex|usps) app\b",
    r"\bcard ending \d{3,4} was used\b.{0,80}\bopen (?:the|your) .{0,20}app\b",
    r"\bpackage (?:was|has been) delivered\b",
    r"\border (?:has )?(?:shipped|arrived|was delivered)\b",
    r"\b(?:i|we) (?:sent|bought|got) you (?:an? )?(?:apple |google play |steam )?gift card\b.{0,40}\b(?:birthday|holiday|present|gift)\b",
    r"\b(?:paid|paying) you back\b.{0,25}\b(?:venmo|zelle|cash app)\b",
    r"\b(?:buy|purchase|get|need to buy|need to purchase) (?:some |a few )?(?:apple |google play |steam )?gift cards? for (?:teacher appreciation|a birthday|the holidays?|christmas|graduation|a present)\b",
]

SAFE_CREDENTIAL_NOTICE_PATTERNS = [
    r"\b(?:will|would) never ask\b.{0,50}\b(?:password|code|ssn|account number|card number)\b",
    r"\bnever (?:send|share|give)\b.{0,50}\b(?:password|code|ssn|account number|card number)\b",
    r"\bdo not (?:send|share|give)\b.{0,50}\b(?:password|code|ssn|account number|card number)\b",
]

NEGATED_PAYMENT_PATTERNS = [
    r"\bno (?:fee|payment|deposit|purchase)(?: or (?:fee|payment|deposit|purchase))? (?:is )?required\b",
    r"\b(?:fee|payment|deposit) is not required\b",
    r"\bno need to (?:pay|send|transfer)\b",
    r"\bdo not (?:pay|send|transfer)\b",
]

SAFE_PRIZE_PATTERNS = [
    r"\b(?:office|school|church|family) raffle\b.{0,60}\bno (?:fee|payment)\b",
    r"\bwon\b.{0,40}\bno (?:fee|payment|purchase) (?:is )?required\b",
]

SAFE_EMERGENCY_CONTEXT_PATTERNS = [
    r"\b(?:school play|stage play|movie|book|tv show|video game|board game)\b",
    r"\b(?:doing|feeling) fine\b.{0,40}\bno money\b",
    r"\bno money (?:is )?(?:needed|required)\b",
    r"\b(?:already home|safe now|everything is okay|everything is fine)\b",
]

FAKE_CHECK_PATTERNS = [
    r"\bdeposit (?:this|the|a) check\b",
    r"\bmobile deposit\b.{0,40}\bcheck\b",
    r"\bcheck\b.{0,60}\b(?:buy|purchase) (?:equipment|supplies|gift cards?)\b",
    r"\b(?:cashier's|certified) check\b.{0,60}\b(?:send|refund|wire|pay)\b",
]

OVERPAYMENT_PATTERNS = [
    r"\b(?:sent|paid|wrote the check for) (?:too much|extra|more than)\b",
    r"\brefund (?:the|me|my) (?:difference|extra|balance)\b",
    r"\bsend (?:the|me) (?:difference|extra|balance) back\b",
]

TOLL_PATTERNS = [
    r"\b(?:unpaid|overdue|outstanding) tolls?\b",
    r"\btoll (?:balance|charge|violation|notice|fee)\b",
    r"\b(?:e-?zpass|sunpass|fastrak|txtag|illinois tollway)\b",
]

EMPLOYMENT_FEE_PATTERNS = [
    r"\b(?:job|employment|employer|recruiter|training)\b.{0,70}\b(?:fee|deposit|gift card|check|equipment|vendor)\b",
    r"\bpay\b.{0,30}\btraining fee\b",
]

MARKETPLACE_FEE_PATTERNS = [
    r"\b(?:marketplace|buyer|seller|courier|pickup agent|shipping agent)\b.{0,70}\b(?:fee|insurance|deposit|payment|zelle|venmo)\b",
    r"\bpay\b.{0,30}\b(?:insurance|courier|shipping) fee\b",
]

VAGUE_ACCOUNT_ALERT_PATTERNS = [
    r"\byour account (?:needs attention|requires attention|has a problem)\b",
    r"\baccount alert\b.{0,50}\b(?:call|reply|verify|click)\b",
]

ROMANCE_CONTEXT_PATTERNS = [
    r"\b(?:my love|love you|soulmate|darling|sweetheart)\b.{0,120}\b(?:send|wire|pay|need)\b.{0,60}\b(?:money|\$\d|bitcoin|crypto|ticket|fee)\b",
    r"\b(?:stationed|deployed|working) overseas\b.{0,120}\b(?:bank account|money|wire|gift card|bitcoin)\b",
    r"\b(?:plane ticket|travel to see you|come visit you)\b.{0,80}\b(?:send|need|pay|money|\$\d)\b",
]

INVESTMENT_PROMISE_PATTERNS = [
    r"\bguaranteed\b.{0,30}\b(?:return|profit|income)\b",
    r"\bdouble your money\b",
    r"\b(?:zero|no) risk\b.{0,40}\b(?:return|profit|investment|trading)\b",
    r"\b(?:deposit|invest)\b.{0,35}\b(?:bitcoin|btc|crypto|cryptocurrency)\b",
]

GIFT_CARD_REQUEST_PATTERNS = [
    r"\b(?:buy|purchase|get|send|provide|text|share|photo|photograph|scratch)\b.{0,60}\b(?:apple|google play|steam)?\s*gift cards?\b",
    r"\b(?:need|needs) (?:you|u) to (?:buy|purchase|get|send)\b.{0,45}\b(?:apple|google play|steam)?\s*gift cards?\b",
    r"\b(?:apple|google play|steam) cards?\b.{0,60}\b(?:buy|purchase|send|share|text|photo|back|pin|code)\b",
    r"\b(?:gift cards?|apple cards?|google play cards?|steam cards?)\b.{0,45}\b(?:send|share|text|photo|photograph|scratch)\b.{0,30}\b(?:code|pin|back)\b",
]

ORGANIZATIONS = {
    "Chase": ["chase"],
    "Wells Fargo": ["wells fargo"],
    "Bank of America": ["bank of america"],
    "Citibank": ["citibank", "citi bank", "citi"],
    "PayPal": ["paypal"],
    "Amazon": ["amazon"],
    "Apple": ["apple"],
    "Microsoft": ["microsoft"],
    "USPS": ["usps", "postal service", "united states postal service"],
    "FedEx": ["fedex"],
    "UPS": ["ups"],
    "IRS": ["irs", "internal revenue service"],
    "Social Security Administration": ["social security administration", "ssa"],
    "Medicare": ["medicare"],
}

OFFICIAL_DOMAINS = {
    "Chase": ["chase.com"],
    "Wells Fargo": ["wellsfargo.com"],
    "Bank of America": ["bankofamerica.com"],
    "Citibank": ["citi.com", "citibank.com"],
    "PayPal": ["paypal.com"],
    "Amazon": ["amazon.com"],
    "Apple": ["apple.com"],
    "Microsoft": ["microsoft.com"],
    "USPS": ["usps.com", "uspis.gov"],
    "FedEx": ["fedex.com"],
    "UPS": ["ups.com"],
    "IRS": ["irs.gov"],
    "Social Security Administration": ["ssa.gov"],
    "Medicare": ["medicare.gov"],
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.one",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".live", ".support", ".info", ".shop",
    ".buzz", ".work", ".rest", ".cam", ".icu", ".mom", ".monster",
}

# Finds both complete URLs and common bare domains such as bit.ly/abc.
URL_RE = re.compile(
    r"(?:(?:https?://|www\.)[^\s<>()]+|(?<!@)\b(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:com|net|org|gov|edu|io|co|us|info|biz|xyz|top|click|live|support|shop|buzz|work|rest|cam|ly|icu|mom|monster)(?:/[^\s<>()]*)?)",
    re.IGNORECASE,
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)")


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.findall(text):
        cleaned = match.rstrip(".,;:!?)]}\"'")
        if cleaned and cleaned.lower() not in seen:
            urls.append(cleaned)
            seen.add(cleaned.lower())
    return urls


def normalize_domain(url: str) -> str:
    candidate = url if url.startswith(("http://", "https://")) else f"https://{url}"
    return urlparse(candidate).netloc.lower().split(":")[0].removeprefix("www.")


def _contains_phrase(text: str, phrase: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(phrase)}(?!\w)", text, re.IGNORECASE) is not None


def find_terms(text: str, terms: list[str]) -> list[str]:
    return [term for term in terms if _contains_phrase(text, term)]


def find_organizations(text: str) -> list[str]:
    lowered = text.lower()
    return [
        organization
        for organization, aliases in ORGANIZATIONS.items()
        if any(_contains_phrase(lowered, alias) for alias in aliases)
    ]


def domain_matches(domain: str, official_domains: list[str]) -> bool:
    return any(domain == official or domain.endswith(f".{official}") for official in official_domains)


def _matches_any(patterns: list[str], text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE | re.DOTALL) for pattern in patterns)


def analyze_rules(text: str) -> dict:
    lowered = text.lower()
    urls = extract_urls(text)
    domains = [normalize_domain(url) for url in urls]
    phones = PHONE_RE.findall(text)

    urgency = find_terms(text, URGENCY_TERMS)
    threats = find_terms(text, THREAT_TERMS)
    credentials = find_terms(text, CREDENTIAL_TERMS)
    risky_payments = find_terms(text, RISKY_PAYMENT_TERMS)
    secrecy = find_terms(text, SECRECY_TERMS)
    emergencies = find_terms(text, EMERGENCY_TERMS)
    new_number = find_terms(text, NEW_NUMBER_TERMS)
    family_references = find_terms(text, FAMILY_REFERENCE_TERMS)
    remote_access = find_terms(text, REMOTE_ACCESS_TERMS)
    security_alerts = find_terms(text, SECURITY_ALERT_TERMS)
    prizes = find_terms(text, PRIZE_TERMS)
    organizations = find_organizations(text)

    if _matches_any([
        r"\b(?:virus|malware)\b.{0,30}\b(?:detected|found|identified)\b",
        r"\b(?:detected|found|identified)\b.{0,30}\b(?:virus|malware)\b",
        r"\b(?:device|computer|iphone|account)\b.{0,30}\b(?:infected|hacked|compromised)\b",
    ], lowered) and not security_alerts:
        security_alerts = ["security alert"]

    action_request = any(_contains_phrase(lowered, term) for term in ACTION_TERMS)
    money_request = _matches_any(MONEY_REQUEST_PATTERNS, lowered)
    safe_code_notice = _matches_any(SAFE_CODE_NOTICE_PATTERNS, lowered)
    code_request = _matches_any(CODE_REQUEST_PATTERNS, lowered) and not safe_code_notice
    routine_context = _matches_any(ROUTINE_PATTERNS, lowered)
    safe_context = _matches_any(SAFE_CONTEXT_PATTERNS, lowered)
    safe_credential_notice = _matches_any(SAFE_CREDENTIAL_NOTICE_PATTERNS, lowered)
    negated_payment = _matches_any(NEGATED_PAYMENT_PATTERNS, lowered)
    safe_prize_context = _matches_any(SAFE_PRIZE_PATTERNS, lowered)
    safe_emergency_context = _matches_any(SAFE_EMERGENCY_CONTEXT_PATTERNS, lowered)
    fake_check = _matches_any(FAKE_CHECK_PATTERNS, lowered)
    overpayment = _matches_any(OVERPAYMENT_PATTERNS, lowered)
    toll_demand = _matches_any(TOLL_PATTERNS, lowered)
    employment_fee = _matches_any(EMPLOYMENT_FEE_PATTERNS, lowered)
    marketplace_fee = _matches_any(MARKETPLACE_FEE_PATTERNS, lowered)
    vague_account_alert = _matches_any(VAGUE_ACCOUNT_ALERT_PATTERNS, lowered)
    romance_money_context = _matches_any(ROMANCE_CONTEXT_PATTERNS, lowered)
    investment_promise = _matches_any(INVESTMENT_PROMISE_PATTERNS, lowered)
    gift_card_request = _matches_any(GIFT_CARD_REQUEST_PATTERNS, lowered)

    if negated_payment and not _matches_any([
        r"\b(?:pay|send|transfer|wire|remit|buy|purchase)\b.{0,50}\b(?:\$\s?\d|money|fee|bitcoin|btc|crypto|gift cards?|zelle|venmo)\b"
    ], lowered):
        money_request = False
    if safe_prize_context:
        prizes = []
        money_request = False
    if safe_credential_notice:
        credentials = []
    if safe_emergency_context and not money_request and not secrecy:
        emergencies = []
    if safe_context and not _matches_any([
        r"\b(?:send|share|text|photo|photograph|scratch)\b.{0,45}\b(?:code|pin|back)\b",
        r"\b(?:boss|manager|ceo|supervisor|lawyer)\b.{0,60}\b(?:gift cards?|apple cards?|google play cards?|steam cards?)\b",
    ], lowered):
        gift_card_request = False
        money_request = False
        risky_payments = []

    evidence: list[str] = []
    points = 0
    flags: set[str] = set()

    if urls:
        flags.add("url")
        if action_request:
            evidence.append("It directs you to act through a link in the message.")
            points += 10

    if any(domain in SHORTENERS for domain in domains):
        flags.add("shortened_url")
        evidence.append("The link hides its destination behind a URL-shortening service.")
        points += 18

    if any(any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) for domain in domains):
        flags.add("suspicious_tld")
        evidence.append("The link uses an unusual domain ending that is commonly used for lookalike sites.")
        points += 18

    for organization in organizations:
        official_domains = OFFICIAL_DOMAINS.get(organization, [])
        if domains and official_domains and not any(domain_matches(domain, official_domains) for domain in domains):
            flags.add("domain_mismatch")
            evidence.append(f"It uses {organization}'s name, but the link is not on an official {organization} domain.")
            points += 30
            break

    if urgency:
        flags.add("urgency")
        evidence.append("It pressures you to act quickly instead of giving you time to verify the request.")
        points += 10

    if threats:
        flags.add("threat")
        evidence.append("It uses threats or serious consequences to pressure you into acting.")
        points += 18

    if code_request:
        flags.add("code_request")
        evidence.append("It asks for a one-time verification code, which could let someone take over an account.")
        points += 42
    elif credentials and not safe_code_notice:
        flags.add("credential_request")
        evidence.append("It asks for or refers to sensitive account or identity information.")
        points += 24

    risky_payment_request = bool(risky_payments) and (
        money_request
        or gift_card_request
        or _matches_any([
            r"\b(?:send|buy|purchase|pay|wire|transfer|refund|reimburse|share|provide|text|photo|photograph|scratch)\b.{0,60}\b(?:gift cards?|bitcoin|btc|crypto|zelle|venmo|cash app|western union|moneygram|pin|codes?)\b",
            r"\b(?:gift cards?|bitcoin|btc|crypto|zelle|venmo|cash app|western union|moneygram)\b.{0,60}\b(?:send|buy|purchase|pay|wire|transfer|refund|reimburse|share|provide|text|photo)\b",
        ], lowered)
    )

    if gift_card_request:
        flags.add("gift_card_request")
        if not risky_payments:
            risky_payments = ["gift cards"]

    if risky_payment_request or gift_card_request:
        flags.add("risky_payment")
        method = ", ".join(risky_payments[:2]) if risky_payments else "gift cards"
        evidence.append(f"It requests a hard-to-reverse payment method such as {method}.")
        points += 32

    if money_request and not (risky_payment_request or gift_card_request):
        flags.add("money_request")
        evidence.append("It asks you to send money or pay an unexpected charge.")
        points += 18
    elif money_request:
        flags.add("money_request")

    if secrecy:
        flags.add("secrecy")
        evidence.append("It tells you to keep the situation secret, which is a common scam tactic.")
        points += 20

    if emergencies:
        flags.add("emergency")
        evidence.append("It describes an emergency designed to trigger an emotional, immediate response.")
        points += 16

    if new_number:
        flags.add("new_number")
        evidence.append("It claims to be using a new or temporary number, so the sender should be verified separately.")
        points += 10

    if fake_check:
        flags.add("fake_check")
        evidence.append("It asks you to deposit a check and then spend or return part of the money, a classic fake-check setup.")
        points += 34

    if overpayment:
        flags.add("overpayment")
        evidence.append("It claims too much money was sent and asks you to return the difference, a common overpayment scam.")
        points += 34

    if toll_demand:
        flags.add("toll_demand")
        evidence.append("It claims you owe an unpaid toll and directs you to make a payment through the message.")
        points += 22

    if remote_access:
        flags.add("remote_access")
        evidence.append("It asks for remote-access software that could let a stranger control the device.")
        points += 32

    if security_alerts:
        flags.add("security_alert")
        evidence.append("It makes an alarming claim about a virus, hack, or compromised device.")
        points += 20

    if prizes:
        flags.add("prize")
        evidence.append("It claims you won a prize, a common setup for collecting fees or personal information.")
        points += 20

    if employment_fee:
        flags.add("employment_fee")
        evidence.append("It connects a job opportunity with an upfront fee, check, or equipment purchase.")
        points += 24

    if marketplace_fee:
        flags.add("marketplace_fee")
        evidence.append("It asks for an unusual fee or outside payment as part of an online sale.")
        points += 24

    if vague_account_alert:
        flags.add("vague_account_alert")
        evidence.append("It gives a vague account warning and asks you to contact the sender without explaining what happened.")
        points += 20

    if romance_money_context:
        flags.add("romance_money")
        evidence.append("It combines emotional or romantic language with a request for money.")
        points += 28

    if investment_promise:
        flags.add("investment_promise")
        evidence.append("It promises unusually high or guaranteed investment returns, which legitimate investments cannot guarantee.")
        points += 28

    if organizations and flags.intersection({
        "url", "domain_mismatch", "urgency", "threat", "code_request",
        "credential_request", "money_request", "risky_payment", "remote_access",
        "security_alert", "vague_account_alert",
    }):
        flags.add("organization_impersonation")
        points += 5

    if phones and (
        security_alerts
        or remote_access
        or vague_account_alert
        or (organizations and "call" in lowered)
        or ("account" in lowered and "call" in lowered)
    ):
        flags.add("call_back_number")
        evidence.append("It provides a phone number in an unsolicited account, security, or support warning.")
        points += 16

    if text.count("!") >= 3:
        flags.add("excessive_punctuation")
        evidence.append("It uses excessive punctuation to intensify the pressure.")
        points += 3

    # Safe context only offsets weak, informational signals. It never cancels a
    # payment request, credential request, deceptive link, threat, or emergency.
    dangerous_flags = flags.intersection({
        "domain_mismatch", "shortened_url", "suspicious_tld", "threat",
        "code_request", "credential_request", "money_request", "risky_payment",
        "secrecy", "emergency", "fake_check", "overpayment", "remote_access",
        "security_alert", "prize", "employment_fee", "marketplace_fee",
        "toll_demand", "romance_money", "investment_promise",
    })
    is_safe_context = safe_context and not dangerous_flags
    meaningful_flags = flags.difference({"url", "organization_impersonation"})
    is_routine = (routine_context or is_safe_context) and not dangerous_flags and not code_request
    is_clear_benign = not dangerous_flags and not vague_account_alert and (
        is_routine or (not meaningful_flags and not money_request and not code_request and not action_request)
    )

    return {
        "urls": urls,
        "domains": domains,
        "phones": phones,
        "urgency_terms": urgency,
        "threat_terms": threats,
        "credential_terms": credentials,
        "risky_payment_terms": risky_payments,
        "organizations": organizations,
        "evidence": evidence,
        "signal_flags": sorted(flags),
        "risk_points": min(points, 100),
        "rule_boost": min(points / 100.0, 1.0),
        "money_request": money_request,
        "code_request": code_request,
        "safe_code_notice": safe_code_notice,
        "family_reference": bool(family_references),
        "is_routine": is_routine,
        "is_clear_benign": is_clear_benign,
        "safe_context": is_safe_context,
        "safe_credential_notice": safe_credential_notice,
        "negated_payment": negated_payment,
        "safe_prize_context": safe_prize_context,
        "safe_emergency_context": safe_emergency_context,
        "action_request": action_request,
        "gift_card_request": gift_card_request,
        "romance_money_context": romance_money_context,
        "investment_promise": investment_promise,
        "employment_fee": employment_fee,
        "marketplace_fee": marketplace_fee,
        "vague_account_alert": vague_account_alert,
    }
