"""
SafeGuard AI - Prediction & Risk Calculation Engine
"""

import os
import joblib
import numpy as np
from typing import Dict, List, Any

from src.preprocessing import clean_text
from src.feature_extraction import extract_heuristic_indicators, ALL_CATEGORIES
from src.url_analyzer import analyze_urls_in_text
from src.train import train_and_evaluate_models


class SafeguardPredictor:
    def __init__(self, model_dir: str = "models", data_path: str = "data/demo_dataset.csv"):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if not os.path.isabs(model_dir):
            self.model_dir = os.path.join(base_dir, model_dir)
        else:
            self.model_dir = model_dir
            
        if not os.path.isabs(data_path):
            self.data_path = os.path.join(base_dir, data_path)
        else:
            self.data_path = data_path

        self.model = None
        self.vectorizer = None
        self.mlb = None
        self._ensure_loaded()
        
    def _ensure_loaded(self):
        """Loads model artifacts or triggers model training if missing."""
        model_path = os.path.join(self.model_dir, "multi_label_model.joblib")
        vec_path = os.path.join(self.model_dir, "tfidf_vectorizer.joblib")
        mlb_path = os.path.join(self.model_dir, "mlb.joblib")
        
        if not (os.path.exists(model_path) and os.path.exists(vec_path) and os.path.exists(mlb_path)):
            print("⚡ Model artifacts missing. Training initial models on demo dataset...")
            train_and_evaluate_models(data_path=self.data_path, output_dir=self.model_dir)
            
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vec_path)
        self.mlb = joblib.load(mlb_path)


    def predict(self, text: str, threshold: float = 0.30, url_analysis: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes end-to-end multi-label threat detection and risk scoring,
        combining NLP model probabilities, text heuristics, and URL security intelligence.
        """
        if not text or not text.strip():
            return self._empty_response()

        # 1. Feature Extraction & Vectorization
        X_vec = self.vectorizer.transform([text])
        
        # 2. ML Inference & Class Probabilities
        ml_probs = {}
        classes = self.mlb.classes_
        
        # MultiOutputClassifier handles estimators
        for idx, estimator in enumerate(self.model.estimators_):
            cls_name = classes[idx]
            if hasattr(estimator, "predict_proba"):
                prob = estimator.predict_proba(X_vec)[0][1]
            elif hasattr(estimator, "decision_function"):
                df_val = estimator.decision_function(X_vec)[0]
                prob = float(1 / (1 + np.exp(-df_val))) # Sigmoid scaling
            else:
                prob = float(estimator.predict(X_vec)[0])
            ml_probs[cls_name] = round(float(prob), 4)

        # 3. Static URL Analysis Integration
        if url_analysis is None:
            url_analysis = analyze_urls_in_text(text)

        url_risk_weight_sum = 0.0
        has_malware_url = False
        has_phishing_url = False
        has_suspicious_url = False

        for url_info in url_analysis:
            risk_w = url_info.get("risk_weight", 0.0)
            url_risk_weight_sum += risk_w
            
            if url_info.get("has_malware_ext"):
                has_malware_url = True
                ml_probs["SCAM"] = max(ml_probs.get("SCAM", 0.0), 0.88)
                ml_probs["PHISHING"] = max(ml_probs.get("PHISHING", 0.0), 0.80)
            
            if url_info.get("is_ip") or "CREDENTIAL_PHISHING" in url_info.get("threat_tags", []):
                has_phishing_url = True
                ml_probs["PHISHING"] = max(ml_probs.get("PHISHING", 0.0), 0.85)
                ml_probs["CREDENTIAL_THEFT"] = max(ml_probs.get("CREDENTIAL_THEFT", 0.0), 0.80)
                
            if "HIGH_RISK_TLD" in url_info.get("threat_tags", []) or "URL_SHORTENER" in url_info.get("threat_tags", []):
                ml_probs["PHISHING"] = max(ml_probs.get("PHISHING", 0.0), 0.65)

            if "SKETCHY_DOMAIN_KEYWORD" in url_info.get("threat_tags", []) or "NUMERIC_DOMAIN_SPOOF" in url_info.get("threat_tags", []) or "PARKED_SUSPICIOUS_IP" in url_info.get("threat_tags", []):
                has_suspicious_url = True
                ml_probs["SCAM"] = max(ml_probs.get("SCAM", 0.0), 0.85)
                ml_probs["PHISHING"] = max(ml_probs.get("PHISHING", 0.0), 0.75)

        # 4. Heuristic Indicator Detection
        indicators = extract_heuristic_indicators(text)
        
        # Add URL specific indicators to detected_indicators list if URLs are suspicious
        for url_info in url_analysis:
            if url_info.get("suspicious"):
                for url_ind in url_info.get("indicators", []):
                    if not any(i.get("name") == f"URL Anomaly: {url_ind}" for i in indicators):
                        indicators.append({
                            "id": "URL_ANOMALY",
                            "name": f"URL Anomaly",
                            "explanation": url_ind,
                            "weight": round(url_info.get("risk_weight", 1.5) / max(len(url_info.get("indicators", [1])), 1), 2),
                            "matched_snippets": [url_info.get("url")]
                        })

        indicator_weight_sum = sum(ind["weight"] for ind in indicators) + url_risk_weight_sum
        
        # Boost specific categories based on strong heuristic rules
        for ind in indicators:
            if ind["id"] == "BLACKMAIL_LEAK":
                ml_probs["BLACKMAIL"] = max(ml_probs.get("BLACKMAIL", 0.0), 0.85)
                ml_probs["FINANCIAL_COERCION"] = max(ml_probs.get("FINANCIAL_COERCION", 0.0), 0.70)
                ml_probs["THREAT"] = max(ml_probs.get("THREAT", 0.0), 0.75)
            elif ind["id"] == "OTP_CREDENTIAL_REQ":
                ml_probs["CREDENTIAL_THEFT"] = max(ml_probs.get("CREDENTIAL_THEFT", 0.0), 0.90)
                ml_probs["PHISHING"] = max(ml_probs.get("PHISHING", 0.0), 0.80)
            elif ind["id"] == "PHYSICAL_THREAT":
                ml_probs["THREAT"] = max(ml_probs.get("THREAT", 0.0), 0.85)
            elif ind["id"] == "CYBERBULLYING_TEXT":
                ml_probs["CYBERBULLYING"] = max(ml_probs.get("CYBERBULLYING", 0.0), 0.75)
            elif ind["id"] == "UNREALISTIC_PROMISE":
                ml_probs["INVESTMENT_SCAM"] = max(ml_probs.get("INVESTMENT_SCAM", 0.0), 0.80)
                ml_probs["SCAM"] = max(ml_probs.get("SCAM", 0.0), 0.80)
            elif ind["id"] == "SUSPICIOUS_JOB":
                ml_probs["JOB_SCAM"] = max(ml_probs.get("JOB_SCAM", 0.0), 0.80)
                ml_probs["SCAM"] = max(ml_probs.get("SCAM", 0.0), 0.75)
            elif ind["id"] == "BANK_IMPERSONATION":
                ml_probs["PHISHING"] = max(ml_probs.get("PHISHING", 0.0), 0.65)

        # Evaluate threat probabilities vs SAFE
        threat_probs = {k: v for k, v in ml_probs.items() if k != "SAFE"}
        max_threat_prob = max(threat_probs.values()) if threat_probs else 0.0

        # Determine active threat categories above confidence threshold
        active_categories = []
        for cat_name, prob in threat_probs.items():
            if prob >= threshold:
                active_categories.append({
                    "category": cat_name,
                    "confidence": round(prob * 100, 1),
                    "raw_prob": prob
                })
                
        # Sort by confidence descending
        active_categories.sort(key=lambda x: x["confidence"], reverse=True)
        
        # If no threat indicators exist or all URLs are verified clean with zero text threat indicators, force SAFE
        all_urls_clean = (len(url_analysis) > 0) and all(u.get("risk_weight", 0.0) == 0.0 for u in url_analysis)
        no_text_indicators = len([i for i in indicators if i.get("id") != "SUSPICIOUS_URL"]) == 0
        
        if not active_categories or (all_urls_clean and no_text_indicators) or (ml_probs.get("SAFE", 0.0) >= 0.70 and max_threat_prob < 0.50 and indicator_weight_sum < 1.0):
            is_safe = True
            active_categories = [{
                "category": "SAFE",
                "confidence": round(max(ml_probs.get("SAFE", 0.95), 0.95) * 100, 1),
                "raw_prob": max(ml_probs.get("SAFE", 0.95), 0.95)
            }]

        # 5. Composite Risk Score Calculation (0 - 100)
        if active_categories[0]["category"] == "SAFE":
            if indicator_weight_sum < 0.5:
                raw_risk = 0.0
            else:
                raw_risk = 8.0 * indicator_weight_sum
        else:
            base_risk = max_threat_prob * 55.0
            indicator_bonus = indicator_weight_sum * 6.0
            severity_bonus = 0.0
            
            # Severity multipliers for severe threats
            primary_cat = active_categories[0]["category"]
            if primary_cat in ["BLACKMAIL", "THREAT"]:
                severity_bonus = 25.0
            elif primary_cat in ["CREDENTIAL_THEFT", "PHISHING", "FINANCIAL_COERCION"]:
                severity_bonus = 20.0
            elif primary_cat in ["SCAM", "INVESTMENT_SCAM", "JOB_SCAM"]:
                severity_bonus = 15.0

            if has_malware_url or has_phishing_url or has_suspicious_url:
                severity_bonus += 20.0
                
            raw_risk = base_risk + indicator_bonus + severity_bonus

        risk_score = int(min(max(round(raw_risk), 0), 100))

        # 6. Risk Level Classification
        if risk_score <= 25:
            risk_level = "🟢 LOW RISK"
            risk_color = "#28a745"
        elif risk_score <= 55:
            risk_level = "🟡 MEDIUM RISK"
            risk_color = "#ffc107"
        elif risk_score <= 80:
            risk_level = "🔴 HIGH RISK"
            risk_color = "#dc3545"
        else:
            risk_level = "🚨 CRITICAL RISK"
            risk_color = "#8b0000"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "predicted_categories": active_categories,
            "detected_indicators": indicators,
            "ml_probabilities": ml_probs
        }

    def _empty_response(self) -> Dict[str, Any]:
        return {
            "risk_score": 0,
            "risk_level": "🟢 LOW RISK",
            "risk_color": "#28a745",
            "predicted_categories": [{"category": "SAFE", "confidence": 100.0, "raw_prob": 1.0}],
            "detected_indicators": [],
            "ml_probabilities": {"SAFE": 1.0}
        }


if __name__ == "__main__":
    predictor = SafeguardPredictor()
    test_msg = "Pay me ₹10,000 or I will publish your private photos."
    res = predictor.predict(test_msg)
    print("Test Prediction:")
    print("Risk Level:", res["risk_level"], "| Score:", res["risk_score"])
    print("Categories:", res["predicted_categories"])
