"""
SafeGuard AI - Prediction & Risk Calculation Engine
"""

import os
import joblib
import numpy as np
from typing import Dict, List, Any

from src.preprocessing import clean_text
from src.feature_extraction import extract_heuristic_indicators, ALL_CATEGORIES
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


    def predict(self, text: str, threshold: float = 0.30) -> Dict[str, Any]:
        """
        Executes end-to-end multi-label threat detection and risk scoring.
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

        # 3. Heuristic Indicator Detection
        indicators = extract_heuristic_indicators(text)
        indicator_weight_sum = sum(ind["weight"] for ind in indicators)
        
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

        # Remove SAFE from active threat consideration if threat score exists
        threat_probs = {k: v for k, v in ml_probs.items() if k != "SAFE"}
        max_threat_prob = max(threat_probs.values()) if threat_probs else 0.0

        # Filter categories meeting confidence threshold
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
        
        # If no threat categories detected above threshold, set SAFE
        if not active_categories:
            active_categories.append({
                "category": "SAFE",
                "confidence": round(ml_probs.get("SAFE", 0.95) * 100, 1),
                "raw_prob": ml_probs.get("SAFE", 0.95)
            })

        # 4. Composite Risk Score Calculation (0 - 100)
        if active_categories[0]["category"] == "SAFE":
            raw_risk = max(10 * indicator_weight_sum, 5.0)
        else:
            base_risk = max_threat_prob * 60.0
            indicator_bonus = indicator_weight_sum * 8.0
            severity_bonus = 0.0
            
            # Severity multipliers for severe threats
            primary_cat = active_categories[0]["category"]
            if primary_cat in ["BLACKMAIL", "THREAT"]:
                severity_bonus = 20.0
            elif primary_cat in ["CREDENTIAL_THEFT", "PHISHING", "FINANCIAL_COERCION"]:
                severity_bonus = 15.0
            elif primary_cat in ["SCAM", "INVESTMENT_SCAM", "JOB_SCAM"]:
                severity_bonus = 10.0
                
            raw_risk = base_risk + indicator_bonus + severity_bonus

        risk_score = int(min(max(round(raw_risk), 0), 100))

        # 5. Risk Level Classification
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
