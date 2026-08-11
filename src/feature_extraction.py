"""
SafeGuard AI - Feature Extraction & Heuristic Indicator Module
"""

import re
from typing import Dict, List, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from src.preprocessing import preprocess_tokens, clean_text

# Define canonical threat target categories
ALL_CATEGORIES = [
    "SAFE",
    "SCAM",
    "PHISHING",
    "FINANCIAL_COERCION",
    "THREAT",
    "BLACKMAIL",
    "CYBERBULLYING",
    "CREDENTIAL_THEFT",
    "INVESTMENT_SCAM",
    "JOB_SCAM"
]

# Indicator regex rules with weights and explanations
INDICATOR_RULES = [
    {
        "id": "URGENCY",
        "name": "High Urgency / Pressure Language",
        "regex": r"\b(immediately|urgent|urgently|within 24 hours|action required today|expires today|deactivated today|account blocked|final notice|act now|do it now|asap|time sensitive)\b",
        "weight": 1.5,
        "explanation": "Pushes victim to act rapidly without verifying facts."
    },
    {
        "id": "BANK_IMPERSONATION",
        "name": "Financial / Bank Impersonation",
        "regex": r"\b(bank|netbanking|hdfc|sbi|icici|chase|paypal|netflix|amazon|apple id|customs|tax authority|police|department)\b",
        "weight": 1.8,
        "explanation": "Claims to be an official institution or authority."
    },
    {
        "id": "OTP_CREDENTIAL_REQ",
        "name": "Credential / OTP Theft Pattern",
        "regex": r"\b(otp|passcode|password|pin|cvv|ssn|netbanking password|login credentials|verification code|verify credentials)\b",
        "weight": 2.5,
        "explanation": "Directly requests sensitive authentication data or secrets."
    },
    {
        "id": "FINANCIAL_DEMAND",
        "name": "Unsolicited Payment / Transfer Request",
        "regex": r"\b(wire|send ₹|send \$|pay ₹|pay \$|transfer|bitcoin|btc|crypto|gift card|registration fee|deposit|upi)\b",
        "weight": 2.0,
        "explanation": "Demands immediate monetary payment, transfer, or crypto deposit."
    },
    {
        "id": "BLACKMAIL_LEAK",
        "name": "Blackmail / Intimate Photo Threat",
        "regex": r"\b(publish|leak|expose|private photos|intimate|embarrassing video|recorded video|webcam|tell your family|send to your contacts)\b",
        "weight": 3.0,
        "explanation": "Coerces victim by threatening to release sensitive media or secrets."
    },
    {
        "id": "PHYSICAL_THREAT",
        "name": "Violence / Extortion Threat",
        "regex": r"\b(hurt you|find out where you live|ruin your life|consequences will be severe|break your|mess you up|track you down|arrest warrant)\b",
        "weight": 2.8,
        "explanation": "Contains explicit threats of harm, physical violence, or police arrest."
    },
    {
        "id": "CYBERBULLYING_TEXT",
        "name": "Harassment / Cyberbullying Attack",
        "regex": r"\b(stupid|pathetic|ugly|disgusting|loser|nobody likes you|quit posting|die|trash|useless)\b",
        "weight": 1.6,
        "explanation": "Targeted derogatory language intended to harass or intimidate."
    },
    {
        "id": "UNREALISTIC_PROMISE",
        "name": "Unrealistic Reward / Investment Scam",
        "regex": r"\b(guaranteed|100% return|double your money|lottery|won \$|won ₹|crypto arbitrage|daily profit|free iphone|risk-free)\b",
        "weight": 2.0,
        "explanation": "Promises unrealistic monetary returns or prize winnings."
    },
    {
        "id": "SUSPICIOUS_JOB",
        "name": "Fake Job Offer / Upfront Fee Scam",
        "regex": r"\b(work from home|earn \$[0-9]+/hr|earn ₹[0-9]+/month|liking youtube videos|starter kit|equipment shipment|proofreader job)\b",
        "weight": 1.8,
        "explanation": "Promises high income for minimal work or requests upfront equipment fees."
    },
    {
        "id": "SUSPICIOUS_URL",
        "name": "Suspicious Link / Domain Structure",
        "regex": r"(bit\.ly|tinyurl|\.xyz|\.top|\.ml|\.info|\.site|\.online|\.ru|\.cc|\.work|\.click|\.tk|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|http://|\.exe|\.apk|\.scr|\.bat|\.vbs|\.zip|\.msi)",
        "weight": 2.0,
        "explanation": "Contains links pointing to unverified, shortened, unencrypted HTTP, or non-standard domains."
    }
]


def create_vectorizer() -> TfidfVectorizer:
    """Creates a configured TF-IDF vectorizer for text feature extraction."""
    return TfidfVectorizer(
        preprocessor=preprocess_tokens,
        ngram_range=(1, 2),
        min_df=1,
        max_features=2500,
        sublinear_tf=True
    )


def extract_heuristic_indicators(text: str) -> List[Dict[str, Any]]:
    """
    Scans input message against security heuristic indicator patterns.
    Returns list of detected indicator objects.
    """
    detected = []
    text_lower = text.lower()
    
    for rule in INDICATOR_RULES:
        matches = re.findall(rule["regex"], text_lower)
        if matches:
            detected.append({
                "id": rule["id"],
                "name": rule["name"],
                "explanation": rule["explanation"],
                "weight": rule["weight"],
                "matched_snippets": list(set(matches[:3]))
            })
            
    return detected


if __name__ == "__main__":
    msg = "Pay me $50,000 immediately or I will publish your private photos online at http://bit.ly/leak"
    indicators = extract_heuristic_indicators(msg)
    print(f"Detected {len(indicators)} heuristic indicators:")
    for ind in indicators:
        print(f" - [{ind['id']}] {ind['name']} (Weight: {ind['weight']}) -> {ind['matched_snippets']}")
