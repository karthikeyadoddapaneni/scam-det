"""
SafeGuard AI - Model Training & Evaluation Pipeline
"""

import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.model_selection import train_test_split
from sklearn.multioutput import MultiOutputClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

from sklearn.metrics import (
    accuracy_score,
    hamming_loss,
    f1_score,
    precision_score,
    recall_score,
    classification_report
)

from src.feature_extraction import create_vectorizer, ALL_CATEGORIES

# Optional XGBoost import with graceful fallback
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False


def load_and_prepare_data(csv_path: str):
    """Reads demo dataset and encodes multi-label targets."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset file not found at: {csv_path}")
        
    df = pd.read_csv(csv_path)
    
    # Parse category tags split by '|'
    df["label_list"] = df["categories"].apply(
        lambda x: [c.strip() for c in str(x).split("|") if c.strip()]
    )
    
    mlb = MultiLabelBinarizer(classes=ALL_CATEGORIES)
    y_encoded = mlb.fit_transform(df["label_list"])
    
    return df["text"].tolist(), y_encoded, mlb


def train_and_evaluate_models(data_path: str = "data/demo_dataset.csv", output_dir: str = "models", results_dir: str = "results"):
    """
    Trains multiple ML models (Logistic Regression, Calibrated SVM, Random Forest, GBDT/XGBoost),
    evaluates research metrics, saves artifacts and reports.
    """
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    
    print("[+] Loading dataset...")
    texts, Y, mlb = load_and_prepare_data(data_path)
    print(f"Dataset loaded: {len(texts)} samples, {Y.shape[1]} target classes.")
    
    # Train / Test Split
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        texts, Y, test_size=0.25, random_state=42
    )
    
    print("[+] Extracting TF-IDF features...")
    vectorizer = create_vectorizer()
    X_train = vectorizer.fit_transform(X_train_raw)
    X_test = vectorizer.transform(X_test_raw)
    
    # Candidate Classifiers
    candidate_models = {
        "Logistic Regression": MultiOutputClassifier(LogisticRegression(max_iter=1000, C=2.0)),
        "Support Vector Machine (Linear)": MultiOutputClassifier(CalibratedClassifierCV(LinearSVC(dual=False, C=1.0))),
        "Random Forest": MultiOutputClassifier(RandomForestClassifier(n_estimators=100, random_state=42)),
        "Gradient Boosting": MultiOutputClassifier(GradientBoostingClassifier(random_state=42))
    }
    
    if HAS_XGBOOST:
        candidate_models["XGBoost"] = MultiOutputClassifier(XGBClassifier(eval_metric="logloss", random_state=42))
        
    eval_results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model_obj = None
    
    print("[*] Training and evaluating classifiers...")
    for model_name, model in candidate_models.items():
        print(f"\n--- Training {model_name} ---")
        model.fit(X_train, y_train)
        
        # Predict on Test set
        y_pred = model.predict(X_test)
        
        # Metrics calculation
        exact_match = accuracy_score(y_test, y_pred)
        h_loss = hamming_loss(y_test, y_pred)
        f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
        f1_micro = f1_score(y_test, y_pred, average="micro", zero_division=0)
        f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        prec_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
        rec_macro = recall_score(y_test, y_pred, average="macro", zero_division=0)
        
        # Detailed class report
        class_report = classification_report(
            y_test, y_pred, target_names=ALL_CATEGORIES, output_dict=True, zero_division=0
        )
        
        eval_results[model_name] = {
            "exact_match_accuracy": float(exact_match),
            "hamming_loss": float(h_loss),
            "f1_macro": float(f1_macro),
            "f1_micro": float(f1_micro),
            "f1_weighted": float(f1_weighted),
            "precision_macro": float(prec_macro),
            "recall_macro": float(rec_macro),
            "class_report": class_report
        }
        
        print(f"Results for {model_name}:")
        print(f"  Exact Match Accuracy: {exact_match:.4f}")
        print(f"  Hamming Loss:          {h_loss:.4f}")
        print(f"  F1 Macro:              {f1_macro:.4f}")
        print(f"  F1 Micro:              {f1_micro:.4f}")
        
        if f1_micro > best_f1:
            best_f1 = f1_micro
            best_model_name = model_name
            best_model_obj = model

    print(f"\n[BEST] Best Model Selected: {best_model_name} (F1 Micro: {best_f1:.4f})")
    
    # Save Best Model, Vectorizer, and MLB
    model_artifact_path = os.path.join(output_dir, "multi_label_model.joblib")
    vectorizer_artifact_path = os.path.join(output_dir, "tfidf_vectorizer.joblib")
    mlb_artifact_path = os.path.join(output_dir, "mlb.joblib")
    results_json_path = os.path.join(results_dir, "metrics_summary.json")
    model_eval_path = os.path.join(output_dir, "evaluation_results.json")
    
    joblib.dump(best_model_obj, model_artifact_path)
    joblib.dump(vectorizer, vectorizer_artifact_path)
    joblib.dump(mlb, mlb_artifact_path)
    
    summary_data = {
        "best_model_name": best_model_name,
        "n_samples": len(texts),
        "n_train": len(X_train_raw),
        "n_test": len(X_test_raw),
        "classes": ALL_CATEGORIES,
        "evaluations": eval_results
    }
    
    with open(results_json_path, "w") as f:
        json.dump(summary_data, f, indent=2)
        
    with open(model_eval_path, "w") as f:
        json.dump(summary_data, f, indent=2)
        
    print(f"[OK] Saved trained model to {model_artifact_path}")
    print(f"[OK] Saved vectorizer to {vectorizer_artifact_path}")
    print(f"[OK] Saved evaluation report to {results_json_path}")
    
    return best_model_obj, vectorizer, mlb, summary_data


if __name__ == "__main__":
    train_and_evaluate_models()
