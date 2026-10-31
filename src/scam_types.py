"""Scam-scenario classification for GoldenGuard.

This module provides broad keyword/pattern scores. ``src.detector`` then applies
contextual overrides using the explainable rule signals so that, for example,
"IRS + gift cards" becomes government impersonation rather than a generic
gift-card category.
"""

from __future__ import annotations

import re


PATTERNS: dict[str, list[tuple[str, int]]] = {
    "grandparent_emergency": [
        (r"\bgrandma\b", 2), (r"\bgrandpa\b", 2),
        (r"\bgrandmother\b", 2), (r"\bgrandfather\b", 2),
        (r"\bgrandson\b", 3), (r"\bgranddaughter\b", 3),
        (r"\bgrandchild\b", 3),
        (r"\b(?:mom|dad|mother|father)\b", 1),
        (r"\b(?:son|daughter|relative|family member|aunt|uncle)\b", 1),
        (r"\b(?:new number|lost my phone|phone broke|temporary number|new phone number)\b", 4),
        (r"\b(?:bail|jail|arrested|lawyer|hospital|accident|stranded|kidnapped|mugged)\b", 3),
        (r"\b(?:don'?t|do not) tell (?:mom|dad|anyone|the family|my parents)\b", 4),
        (r"\b(?:last one i can turn to|please help me|i need your help)\b", 2),
    ],
    "government_impersonation": [
        (r"\birs\b", 5), (r"\binternal revenue service\b", 5),
        (r"\bsocial security administration\b", 5), (r"\bssa\b", 5),
        (r"\bmedicare\b", 4), (r"\bfederal (?:agent|agency)\b", 4),
        (r"\b(?:arrest warrant|legal action|benefits suspended|ssn suspended)\b", 4),
        (r"\bwarrant\b.{0,35}\barrest\b", 4),
    ],
    "package_delivery": [
        (r"\busps\b", 5), (r"\bfedex\b", 5), (r"\bups\b", 5),
        (r"\bpackage\b", 2), (r"\bparcel\b", 2),
        (r"\b(?:delivery|redelivery|shipping) (?:fee|failed|problem|address|attempt)\b", 4),
        (r"\b(?:cannot|could not|unable to) (?:deliver|be delivered)\b", 4),
        (r"\b(?:on hold|held at|delivery failed|address incomplete)\b", 3),
        (r"\btracking (?:number|link|update)\b", 2),
    ],
    "bank_impersonation": [
        (r"\b(?:bank|credit union)\b", 2),
        (r"\bchase\b", 5), (r"\bwells fargo\b", 5),
        (r"\bbank of america\b", 5), (r"\b(?:citi|citibank)\b", 5),
        (r"\bpaypal\b", 4),
        (r"\b(?:account|card) (?:locked|suspended|restricted|compromised|limited)\b", 4),
        (r"\b(?:unusual|suspicious) (?:activity|transaction|charge)\b", 3),
        (r"\b(?:debit|credit) card\b", 2),
        (r"\bfraud department\b", 4),
        (r"\byour account (?:needs|requires) attention\b", 3),
    ],
    "account_takeover": [
        (r"\b(?:verification|one[- ]?time|security|six[- ]?digit) code\b", 4),
        (r"\botp\b", 4),
        (r"\b(?:send|share|tell|give|forward|read me|provide).{0,45}(?:code|otp|passcode)\b", 7),
        (r"\b(?:password|login|account number|routing number)\b", 2),
        (r"\breset your password\b", 3),
    ],
    "gift_card": [
        (r"\bgift cards?\b", 5),
        (r"\bapple (?:gift )?cards?\b", 5),
        (r"\bgoogle play cards?\b", 5),
        (r"\bsteam cards?\b", 5),
        (r"\b(?:scratch|photo|picture|send).{0,25}(?:back|pin|code)\b", 3),
    ],
    "tech_support": [
        (r"\b(?:microsoft|apple|windows) support\b", 5),
        (r"\b(?:virus|malware) (?:detected|found)\b", 5),
        (r"\b(?:computer|device|iphone) (?:infected|hacked|compromised)\b", 5),
        (r"\bremote access\b", 5),
        (r"\b(?:anydesk|teamviewer|supremo|ultraviewer)\b", 6),
        (r"\btech(?:nical)? support\b", 4),
        (r"\bcall (?:support|microsoft|apple|this number|now)\b", 3),
        (r"\bsecurity warning\b", 3),
    ],
    "romance": [
        (r"\bsoulmate\b", 3),
        (r"\b(?:dating app|online relationship|long-distance relationship)\b", 3),
        (r"\b(?:my love|in love with you|sweetheart|darling)\b", 2),
        (r"\b(?:come visit|plane ticket|travel to see you)\b", 3),
        (r"\b(?:military deployment|deployed overseas|stationed overseas|oil rig|overseas contract)\b", 4),
    ],
    "investment_crypto": [
        (r"\b(?:bitcoin|cryptocurrency|crypto|btc)\b", 3),
        (r"\binvestment opportunity\b", 4),
        (r"\bguaranteed (?:return|profit|income)\b", 6),
        (r"\bdouble your money\b", 6),
        (r"\btrading platform\b", 4),
        (r"\b(?:no|zero) risk\b", 3),
        (r"\b(?:deposit|invest) (?:today|now|immediately)\b", 3),
    ],
    "prize_sweepstakes": [
        (r"\b(?:you won|you have won|you've won)\b", 5),
        (r"\b(?:selected as a winner|claim your prize|lottery winner|sweepstakes)\b", 5),
        (r"\b(?:processing|delivery|release) fee\b", 3),
    ],
    "employment": [
        (r"\b(?:job offer|hiring|remote assistant|work from home|new employer|recruiter)\b", 4),
        (r"\b(?:deposit|mobile deposit).{0,30}\bcheck\b", 5),
        (r"\bbuy (?:equipment|supplies)\b", 4),
        (r"\b(?:vendor|payroll|training fee)\b", 3),
    ],
    "marketplace": [
        (r"\b(?:facebook marketplace|marketplace|craigslist|buyer|seller)\b", 3),
        (r"\b(?:overpaid|sent extra|paid too much)\b", 5),
        (r"\brefund (?:the|me|my) (?:difference|extra|balance)\b", 5),
        (r"\b(?:shipping agent|courier|pickup agent)\b", 3),
        (r"\b(?:insurance|courier|shipping) fee\b", 3),
    ],
    "toll_payment": [
        (r"\b(?:unpaid|overdue|outstanding) tolls?\b", 5),
        (r"\btoll (?:balance|charge|violation|notice|fee)\b", 4),
        (r"\b(?:e-?zpass|sunpass|fastrak|txtag|illinois tollway)\b", 5),
    ],
}

CATEGORY_PRIORITY = [
    "government_impersonation", "grandparent_emergency", "account_takeover",
    "package_delivery", "bank_impersonation", "tech_support", "gift_card",
    "romance", "investment_crypto", "prize_sweepstakes", "employment",
    "marketplace", "toll_payment",
]


def classify_scam_type(text: str) -> dict:
    lowered = text.lower()
    scored_results: list[tuple[str, int, list[str]]] = []

    for category, patterns in PATTERNS.items():
        score = 0
        matches: list[str] = []
        for pattern, weight in patterns:
            found = re.search(pattern, lowered, re.IGNORECASE | re.DOTALL)
            if found:
                matches.append(found.group(0))
                score += weight
        scored_results.append((category, score, matches))

    priority = {
        category: len(CATEGORY_PRIORITY) - index
        for index, category in enumerate(CATEGORY_PRIORITY)
    }
    category, score, matches = max(
        scored_results,
        key=lambda item: (item[1], priority.get(item[0], 0)),
    )

    all_scores = {name: category_score for name, category_score, _ in scored_results}
    if score == 0:
        return {
            "scam_type": "unknown",
            "matched_signals": [],
            "category_score": 0,
            "all_category_scores": all_scores,
        }

    return {
        "scam_type": category,
        "matched_signals": matches,
        "category_score": score,
        "all_category_scores": all_scores,
    }
