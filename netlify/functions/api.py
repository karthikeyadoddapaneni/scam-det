"""
SafeGuard AI — Netlify Python Serverless Function Handler
"""

import os
import sys
import json

# Add project root directory to sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from src.predict import SafeguardPredictor
from src.explain import generate_explanation
from src.url_analyzer import analyze_urls_in_text
from src.reputation import ThreatIntelProvider
from src.recommendations import get_safety_recommendations

# Predictor singleton
predictor = None


def handler(event, context):
    """
    AWS Lambda / Netlify Function Handler Signature.
    """
    http_method = event.get("httpMethod", "GET")
    path = event.get("path", "")

    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    }

    if http_method == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": headers,
            "body": ""
        }

    if "health" in path:
        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps({
                "status": "online",
                "system": "SafeGuard AI",
                "platform": "Netlify Serverless Functions"
            })
        }

    if http_method == "POST":
        try:
            body_raw = event.get("body") or "{}"
            data = json.loads(body_raw)
            text = data.get("text", "").strip()

            if not text:
                return {
                    "statusCode": 400,
                    "headers": headers,
                    "body": json.dumps({"status": "error", "message": "Field 'text' is required."})
                }

            global predictor
            if predictor is None:
                predictor = SafeguardPredictor()

            # 1. Prediction
            result = predictor.predict(text)

            # 2. URL Inspection & Reputation
            url_results = analyze_urls_in_text(text)
            threat_intel = ThreatIntelProvider()

            for url_info in url_results:
                try:
                    url_info["threat_reputation"] = threat_intel.check_url_reputation(url_info["url"])
                except Exception as rep_err:
                    url_info["threat_reputation"] = {"status": "UNAVAILABLE", "is_malicious": False}

            result["url_analysis"] = url_results

            # 3. Recommendations & Explanation
            result["recommendations"] = get_safety_recommendations(result["predicted_categories"], url_results)
            result["explanation"] = generate_explanation(result)

            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps({
                    "status": "success",
                    "result": result
                })
            }

        except Exception as e:
            return {
                "statusCode": 500,
                "headers": headers,
                "body": json.dumps({
                    "status": "error",
                    "message": str(e)
                })
            }

    return {
        "statusCode": 404,
        "headers": headers,
        "body": json.dumps({"status": "error", "message": "Endpoint not found"})
    }
