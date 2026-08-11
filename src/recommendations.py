"""
SafeGuard AI - Safety Recommendation Engine
"""

from typing import List, Dict, Any

RECOMMENDATIONS_MAP = {
    "PHISHING": [
        "🚫 Do not click any links or scan QR codes provided in the message.",
        "🌐 Manually navigate to the official website of the organization using your web browser or official mobile app.",
        "🔍 Verify sender email address/phone number carefully against official contact channels."
    ],
    "CREDENTIAL_THEFT": [
        "🔒 Never share OTPs, PINs, passwords, or two-factor authentication codes with anyone, including bank representatives.",
        "🔑 If you entered credentials on a link from this message, immediately change your password on the official portal.",
        "🛡️ Enable multi-factor authentication (MFA) on all financial and social media accounts."
    ],
    "SCAM": [
        "💰 Do not send money, gift cards, or cryptocurrency to unverified claims or unexpected offers.",
        "❓ Remember: If an offer seems too good to be true (e.g. unexpected lottery, free prizes), it is almost certainly a scam.",
        "📢 Report the sender phone number/email to your service provider or cybersecurity portal."
    ],
    "INVESTMENT_SCAM": [
        "📈 Avoid platforms promising 'guaranteed returns', 'risk-free crypto profits', or 'doubling money'.",
        "🏛️ Check whether the investment firm is registered with financial regulatory authorities (e.g. SEC, SEBI, FCA).",
        "🛑 Never transfer cryptocurrency or funds to personal wallet addresses provided in messaging apps."
    ],
    "JOB_SCAM": [
        "💼 Legitimate employers will NEVER ask you to pay upfront money for training, equipment, or background checks.",
        "🏢 Research the company independently via LinkedIn and official corporate careers pages.",
        "📧 Be wary of job offers conducted entirely over WhatsApp, Telegram, or non-corporate email addresses."
    ],
    "BLACKMAIL": [
        "🛑 Do NOT send money or comply with extortion demands. Compliance often leads to further extortion demands.",
        "📸 Preserve all evidence immediately: take clean screenshots of messages, timestamps, phone numbers, and profile details.",
        "⚖️ Report the incident to your local Cyber Crime Police Cell or reporting authority (e.g., ic3.gov, cybercrime.gov.in)."
    ],
    "FINANCIAL_COERCION": [
        "✋ Pause before making any urgent payments. Pressure tactics are designed to disable critical evaluation.",
        "📞 Contact the purported organization or person independently via a known, trusted phone number.",
        "🛡️ Do not share personal financial details, account numbers, or tax information."
    ],
    "THREAT": [
        "🚨 Take threats to your physical safety seriously. Contact local law enforcement emergency services immediately.",
        "📱 Block the sender on messaging platforms and adjust your privacy settings to restrict public access.",
        "📂 Document all threat messages and keep logs intact for police investigation."
    ],
    "CYBERBULLYING": [
        "🚫 Do not engage or respond to hostile messages. Escalating often fuels the harasser.",
        "🛑 Block the user account across all social platforms.",
        "🚩 Report the harassment directly to the platform platform safety team and keep screenshots."
    ],
    "SAFE": [
        "✅ Message appears normal and low risk. Continue exercising standard digital security hygiene.",
        "🔍 Always stay cautious when receiving unexpected attachments or external links."
    ]
}


def get_safety_recommendations(predicted_categories: List[Dict[str, Any]]) -> List[str]:
    """
    Retrieves practical, tailored safety advice based on predicted threat categories.
    """
    advice = []
    seen = set()
    
    for cat_item in predicted_categories:
        cat = cat_item["category"]
        if cat in RECOMMENDATIONS_MAP:
            for rec in RECOMMENDATIONS_MAP[cat]:
                if rec not in seen:
                    advice.append(rec)
                    seen.add(rec)
                    
    if not advice:
        advice = RECOMMENDATIONS_MAP["SAFE"]
        
    return advice
