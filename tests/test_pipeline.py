"""
SafeGuard AI — Pipeline Test Suite
"""

import os
import unittest
from src.preprocessing import clean_text, preprocess_tokens
from src.feature_extraction import extract_heuristic_indicators
from src.url_analyzer import analyze_urls_in_text
from src.predict import SafeguardPredictor
from src.database import init_db, log_analysis, get_summary_analytics, DB_PATH


class TestSafeguardPipeline(unittest.TestCase):

    def test_preprocessing(self):
        text = "URGENT: Send your OTP to http://bank-update.com immediately!"
        cleaned = clean_text(text)
        tokens = preprocess_tokens(text)
        self.assertIn("urgent", cleaned)
        self.assertIn("url_token", cleaned)
        self.assertIsInstance(tokens, str)

    def test_heuristic_indicators(self):
        phishing_text = "Your bank account will be blocked today. Send your OTP immediately to verify."
        indicators = extract_heuristic_indicators(phishing_text)
        indicator_ids = [ind["id"] for ind in indicators]
        self.assertIn("URGENCY", indicator_ids)
        self.assertIn("OTP_CREDENTIAL_REQ", indicator_ids)

    def test_url_analyzer(self):
        text = "Visit http://192.168.1.1/login or http://bit.ly/bank-update"
        urls = analyze_urls_in_text(text)
        self.assertEqual(len(urls), 2)
        self.assertTrue(any(u["is_ip"] for u in urls))
        self.assertTrue(any(u["is_shortened"] for u in urls))

    def test_prediction_engine(self):
        predictor = SafeguardPredictor()
        test_msg = "Pay me ₹10,000 or I will publish your private intimate photos online."
        res = predictor.predict(test_msg)
        self.assertIn("risk_score", res)
        self.assertGreaterEqual(res["risk_score"], 50)
        categories = [c["category"] for c in res["predicted_categories"]]
        self.assertTrue("BLACKMAIL" in categories or "FINANCIAL_COERCION" in categories or "THREAT" in categories)

    def test_malware_url_detection(self):
        predictor = SafeguardPredictor()
        malware_url_msg = "http://suspicious-malware-site.xyz/download.exe"
        res = predictor.predict(malware_url_msg)
        self.assertGreaterEqual(res["risk_score"], 80)
        self.assertNotEqual(res["predicted_categories"][0]["category"], "SAFE")

    def test_safe_message_zero_risk(self):
        predictor = SafeguardPredictor()
        safe_msg = "Hello how are you doing today"
        res = predictor.predict(safe_msg)
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["predicted_categories"][0]["category"], "SAFE")

    def test_database_logging(self):
        test_db = "test_safeguard_temp.db"
        if os.path.exists(test_db):
            try:
                os.remove(test_db)
            except Exception:
                pass
            
        init_db(test_db)
        dummy_res = {
            "risk_score": 90,
            "risk_level": "🚨 CRITICAL RISK",
            "predicted_categories": [{"category": "PHISHING", "confidence": 95.0, "raw_prob": 0.95}],
            "detected_indicators": [{"id": "URGENCY", "name": "Urgency", "weight": 1.5}]
        }
        row_id = log_analysis(dummy_res, "Sample text", db_path=test_db)
        self.assertGreater(row_id, 0)
        analytics = get_summary_analytics(db_path=test_db)
        self.assertEqual(analytics["total_analyzed"], 1)


if __name__ == "__main__":
    unittest.main()
