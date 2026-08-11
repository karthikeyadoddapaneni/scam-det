"""
SafeGuard AI - Explainable AI (XAI) Module
"""

from typing import Dict, List, Any
from src.preprocessing import clean_text


def generate_explanation(prediction_result: Dict[str, Any], text: str) -> Dict[str, Any]:
    """
    Generates plain-language explanation and feature analysis breakdown for a prediction.
    Explicitly separates ML probabilistic predictions from heuristic security rules.
    """
    categories = prediction_result.get("predicted_categories", [])
    indicators = prediction_result.get("detected_indicators", [])
    primary_category = categories[0]["category"] if categories else "SAFE"
    
    reasons = []
    ml_insights = []
    
    # 1. Rule-Based Explanations
    if indicators:
        for ind in indicators:
            reasons.append({
                "type": "Security Pattern Flagged",
                "indicator": ind["name"],
                "explanation": ind["explanation"],
                "matched": ", ".join([f"'{m}'" for m in ind["matched_snippets"]])
            })
            
    # 2. Text Keyword / Contextual Insights
    text_lower = text.lower()
    if "bank" in text_lower or "account" in text_lower or "netbanking" in text_lower:
        ml_insights.append("Message imitates institutional financial language commonly seen in phishing standard operating procedures.")
    if "otp" in text_lower or "password" in text_lower or "pin" in text_lower:
        ml_insights.append("Requests secret authentication factors (OTP/PIN/Passwords) which official entities never ask users to share over text.")
    if "pay" in text_lower or "wire" in text_lower or "transfer" in text_lower or "bitcoin" in text_lower or "crypto" in text_lower:
        ml_insights.append("Identified financial transfer directives urging immediate fund disbursement.")
    if "publish" in text_lower or "leak" in text_lower or "photos" in text_lower or "video" in text_lower:
        ml_insights.append("Coercive blackmail markers attempting reputation damage unless demands are met.")
    if "http" in text_lower or "www" in text_lower or "bit.ly" in text_lower:
        ml_insights.append("Contains hyperlinked web destinations directing users away from trusted applications.")
        
    # 3. Methodological Note
    methodology_note = (
        "This evaluation combines statistical Machine Learning feature probability with deterministic "
        "cybersecurity heuristic pattern matching. High-risk indicators override purely low-frequency terms "
        "to ensure immediate threat detection."
    )
    
    return {
        "primary_category": primary_category,
        "rule_reasons": reasons,
        "contextual_insights": ml_insights,
        "methodology_note": methodology_note
    }
