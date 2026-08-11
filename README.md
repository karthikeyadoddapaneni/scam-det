# 🛡️ SafeGuard AI — Online Safety & Scam Detection System

**SafeGuard AI** is an AI/NLP-powered cybersecurity application designed to analyze online text messages, emails, social media posts, and suspicious communications to detect and classify multi-label digital threats.

This repository serves as both a runnable web application prototype and a structured, reproducible research codebase that can be cited, evaluated, and extended for academic cybersecurity publications.

---

## 1. Project Objective

The primary goal of SafeGuard AI is to provide context-aware risk analysis for digital text messages, evaluating contextual intent rather than relying solely on naive keyword matching. The application evaluates incoming text across 10 defined threat taxonomy categories, calculates a composite Risk Score (0–100), outputs visual risk levels, provides static URL security analysis, presents explainable AI (XAI) indicators, and offers actionable safety guidance.

---

## 2. Research Problem

Online social engineering, digital fraud, phishing, blackmail, and cyberbullying represent growing global threats. Traditional security systems suffer from major limitations:
- **Rule-only keyword filters** yield high false-positive rates and fail to understand contextual nuances.
- **Single-label classifiers** force messages into a single box, whereas real-world threats are frequently compound (e.g., an extortion message that simultaneously constitutes **BLACKMAIL**, **FINANCIAL_COERCION**, and **THREAT**).
- **Black-box neural models** lack interpretability, reducing user trust and actionability.

SafeGuard AI addresses these challenges through a hybrid multi-label machine learning pipeline paired with security indicator heuristics.

---

## 3. System Architecture

```
safeguard-ai/
│
├── app.py                      # Main Streamlit application interface & dashboards
├── requirements.txt            # Python dependencies
├── README.md                   # Complete research documentation & setup guide
├── .gitignore                  # Git ignore rules
│
├── data/
│   └── demo_dataset.csv        # Multi-label demo training & evaluation dataset
│
├── models/                     # Saved model binaries & vectorizers (.joblib)
│   ├── multi_label_model.joblib
│   ├── tfidf_vectorizer.joblib
│   ├── mlb.joblib
│   └── evaluation_results.json
│
├── src/
│   ├── __init__.py
│   ├── preprocessing.py        # Text cleaning, normalization, tokenization
│   ├── feature_extraction.py   # TF-IDF vectorizer & heuristic rule indicators
│   ├── train.py                # Multi-model training & research evaluation engine
│   ├── predict.py              # Combined inference engine & risk scoring (0-100)
│   ├── explain.py              # Explainable AI (XAI) rationale generator
│   ├── url_analyzer.py         # Offline static URL feature analyzer
│   ├── reputation.py           # External threat intelligence provider interface stub
│   ├── database.py             # SQLite database logger & user feedback store
│   └── recommendations.py      # Category-tailored safety recommendation generator
│
├── notebooks/
│   └── model_experiments.ipynb # Jupyter notebook template for research experiments
│
├── results/                    # Saved evaluation artifacts & metrics summary
│   └── metrics_summary.json
│
└── tests/
    └── test_pipeline.py        # Automated test suite
```

---

## 4. Dataset Requirements

> [!IMPORTANT]
> **Demo Data Disclaimer**: The included `data/demo_dataset.csv` contains pre-configured test samples covering all threat categories to allow immediate execution out of the box. It is **DEMO DATA** intended for system verification and UI testing, not for peer-reviewed scientific claims.

### Dataset Format for Paper Experiments
To substitute a scientific or benchmark research dataset (e.g., SMS Spam Collection, Enron Phishing, Cyberbullying Benchmarks):
1. Format your CSV file with two columns:
   - `text`: Raw text message string
   - `categories`: Pipe-separated list of category tags (e.g. `BLACKMAIL|FINANCIAL_COERCION|THREAT` or `SAFE`)
2. Supported labels:
   `SAFE`, `SCAM`, `PHISHING`, `FINANCIAL_COERCION`, `THREAT`, `BLACKMAIL`, `CYBERBULLYING`, `CREDENTIAL_THEFT`, `INVESTMENT_SCAM`, `JOB_SCAM`
3. Save to `data/research_dataset.csv`.
4. Run:
   ```bash
   python src/train.py
   ```

---

## 5. NLP Methodology

The NLP processing pipeline proceeds through the following stages:

```
User Message
   ↓
Text Preprocessing (Normalization, Tokenization, Special Token Preservation)
   ↓
Feature Extraction (TF-IDF N-grams (1, 2) + Security Heuristic Rules)
   ↓
Multi-Output Machine Learning Classifier (Logistic Regression / Calibrated SVM / Random Forest / GBDT)
   ↓
Class Probability Vector Computation
   ↓
Composite Risk Score Calculation (0 – 100)
   ↓
Risk Level Assignment (LOW / MEDIUM / HIGH / CRITICAL)
   ↓
Explainable AI (XAI) Rationale & Safety Recommendations
```

---

## 6. ML Models

The system evaluates four candidate multi-output classification algorithms:
1. **Logistic Regression** (`MultiOutputClassifier` with L2 regularization)
2. **Support Vector Machine** (`CalibratedClassifierCV(LinearSVC)` with probability calibration)
3. **Random Forest Classifier** (Ensemble of 100 decision trees)
4. **Gradient Boosting Classifier / XGBoost** (Sequential gradient boosted decision trees)

---

## 7. Evaluation Methodology

In accordance with multi-label classification research standards, models are evaluated using:
- **Exact Match Ratio (Subset Accuracy)**: Percentage of samples where the predicted set of labels exactly equals the ground truth.
- **Hamming Loss**: Fraction of wrong label predictions to total number of labels.
- **Micro & Macro F1-Scores**: Multi-label harmonic mean of precision and recall.
- **Per-Class Precision, Recall, and Support**: Metrics calculated for each individual threat category.

All metrics are automatically logged to `results/metrics_summary.json` during model training.

---

## 8. Installation Instructions

### Prerequisites
- Python 3.9+ installed.

### Setup Steps
1. Clone or open the project folder:
   ```bash
   cd safeguard-ai
   ```
2. Create and activate a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 9. How to Run the Application

### Step 1: Train Models (Optional — Auto-bootstrapped if missing)
```bash
python src/train.py
```

### Step 2: Run Unit Tests
```bash
python -m unittest tests/test_pipeline.py
```

### Step 3: Launch Streamlit Web App (Local)
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### Step 4: Deploying to Vercel (Serverless)

SafeGuard AI is pre-configured for **1-click Vercel Deployment** using `@vercel/python` serverless functions:

1. Push your repository to GitHub:
   ```bash
   git add .
   git commit -m "Configure Vercel deployment"
   git push origin main
   ```
2. Log in to [Vercel](https://vercel.com) and click **"Add New Project"**.
3. Import your `scam-det` repository.
4. Leave the root directory as `./` and click **"Deploy"**. Vercel will automatically build the `@vercel/python` app using `vercel.json` and `api/index.py`.

Alternatively, deploy via **Vercel CLI**:
```bash
npm install -g vercel
vercel
```

---

## 10. Limitations

- **Language Scope**: Current demo models and vectorizer dictionaries are trained primarily on English text patterns.
- **Static URL Analysis**: The URL module conducts offline static inspection without fetching live domain WHOIS or dynamic HTTP redirects.
- **Demo Dataset Size**: The initial demo dataset is small and intended for prototype verification. Scientific publication requires retraining on larger benchmark datasets.

---

## 11. Future Work

1. **Transformer / BERT Fine-Tuning**: Upgrade feature extraction from TF-IDF to transformer architectures (e.g. `BERT-base`, `RoBERTa`, or `CyberBERT`).
2. **Deep Explainability**: Integrate SHAP (SHapley Additive exPlanations) or LIME for token-level saliency heatmaps.
3. **Live Threat Intelligence Integration**: Connect real-time threat feeds via API keys for AbuseIPDB and VirusTotal.
4. **Multilingual Support**: Extend tokenizers to handle regional languages and code-switched scripts.
#   s c a m - d e t e c t i o n  
 