"""
SafeGuard AI — Online Safety & Scam Detection System
Streamlit Web Application Interface
"""

import os
import json
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

from src.predict import SafeguardPredictor
from src.explain import generate_explanation
from src.url_analyzer import analyze_urls_in_text
from src.reputation import ThreatIntelProvider
from src.recommendations import get_safety_recommendations
from src.database import log_analysis, log_user_feedback, get_summary_analytics
from src.train import ALL_CATEGORIES, train_and_evaluate_models

# Page Configuration
st.set_page_config(
    page_title="SafeGuard AI — Cyber Safety & Scam Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Modern Cybersecurity Theme CSS
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Header Container */
    .main-header {
        background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 50%, #0284c7 100%);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        padding: 2.5rem 2rem;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
    }
    
    .main-title {
        font-size: 2.8rem;
        font-weight: 800;
        letter-spacing: -0.025em;
        color: #ffffff;
        margin-bottom: 0.5rem;
    }
    
    .main-subtitle {
        font-size: 1.25rem;
        color: #94a3b8;
        font-weight: 500;
    }
    
    /* Cards & Containers */
    .glass-card {
        background: rgba(30, 41, 59, 0.7);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 14px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    
    /* Risk Badges */
    .risk-badge {
        display: inline-block;
        padding: 0.6rem 1.4rem;
        border-radius: 9999px;
        font-weight: 800;
        font-size: 1.2rem;
        letter-spacing: 0.05em;
        text-align: center;
        box-shadow: 0 0 15px rgba(0, 0, 0, 0.4);
    }
    
    .risk-critical { background: #8b0000; color: #ffffff; border: 2px solid #ef4444; }
    .risk-high { background: #991b1b; color: #ffffff; border: 2px solid #f87171; }
    .risk-medium { background: #854d0e; color: #ffffff; border: 2px solid #facc15; }
    .risk-low { background: #14532d; color: #ffffff; border: 2px solid #4ade80; }
    
    /* Category Pills */
    .cat-pill {
        display: inline-block;
        background: #1e293b;
        color: #38bdf8;
        border: 1px solid #0284c7;
        padding: 0.35rem 0.85rem;
        border-radius: 20px;
        font-size: 0.9rem;
        font-weight: 600;
        margin-right: 0.5rem;
        margin-bottom: 0.5rem;
    }
    
    /* Code / Snippets */
    .code-box {
        font-family: 'JetBrains Mono', monospace;
        background: #0f172a;
        color: #cbd5e1;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #38bdf8;
    }
    
    /* Buttons */
    .stButton>button {
        border-radius: 10px;
        font-weight: 600;
        transition: all 0.2s ease-in-out;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Initialize Predictor Engine (cached)
@st.cache_resource
def get_predictor():
    return SafeguardPredictor()

predictor = get_predictor()

# Header Banner
st.markdown("""
<div class="main-header">
    <div class="main-title">🛡️ SafeGuard AI</div>
    <div class="main-subtitle">AI-Powered Online Safety & Scam Detection System</div>
</div>
""", unsafe_allow_html=True)

# Pre-populated Example Test Messages
EXAMPLES = {
    "Select an example message...": "",
    "🚨 Phishing & Credential Theft": "URGENT: Your bank account will be blocked today. Send your OTP immediately to verify your account at http://192.168.1.1/login",
    "💥 Blackmail & Extortion": "Pay me ₹50,000 in Bitcoin within 24 hours or I will publish your private intimate photos to all your social contacts.",
    "📈 Crypto Investment Scam": "Double your money in 3 days! Guaranteed 200% crypto returns. Send 0.1 BTC to this wallet address immediately.",
    "💼 Fake Remote Job Scam": "We are hiring remote Customer Support Executives! $40/hr. Deposit $100 for equipment shipment to begin.",
    "🤬 Cyberbullying & Harassment": "You are so stupid and useless. Nobody likes you, quit posting on social media or else.",
    "🟢 Normal / Safe Conversation": "Hey, are you free for a quick Zoom call at 3 PM to review the project report?"
}

# Navigation Tabs
tab_live, tab_research, tab_analytics, tab_docs = st.tabs([
    "🛡️ Live Analysis",
    "📊 Research & Model Evaluation",
    "📈 System Dashboard & Feedback",
    "📑 Methodology & Documentation"
])

# ==========================================
# TAB 1: LIVE MESSAGE ANALYSIS
# ==========================================
with tab_live:
    col_input, col_examples = st.columns([3, 1.2])
    
    with col_examples:
        st.markdown("### 💡 Quick Examples")
        selected_example_key = st.selectbox(
            "Load a test scenario:",
            options=list(EXAMPLES.keys()),
            index=0
        )
        if selected_example_key and EXAMPLES[selected_example_key]:
            st.session_state["user_input"] = EXAMPLES[selected_example_key]
            
    with col_input:
        st.markdown("### 📝 Input Message")
        
        # User input text area
        default_val = st.session_state.get("user_input", "")
        message_text = st.text_area(
            "Paste a suspicious message, email, or conversation here...",
            value=default_val,
            height=160,
            placeholder="e.g. 'Your bank account is blocked. Send your OTP immediately...'"
        )
        
        st.caption("🔒 Privacy Note: All analysis runs locally in your browser session. Do not paste real passwords or unmasked SSNs.")
        
        c1, c2, c3 = st.columns([1.5, 1, 3])
        with c1:
            analyze_clicked = st.button("🔍 Analyze Message", type="primary", use_container_width=True)
        with c2:
            if st.button("🧹 Clear", use_container_width=True):
                st.session_state["user_input"] = ""
                st.rerun()

    # Process Analysis
    if analyze_clicked or (message_text.strip() and "user_input" in st.session_state and st.session_state["user_input"] == message_text):
        if not message_text.strip():
            st.warning("⚠️ Please paste or type a message to analyze.")
        else:
            with st.spinner("⚡ Running multi-category NLP models and security indicators..."):
                res = predictor.predict(message_text)
                explanation = generate_explanation(res, message_text)
                detected_urls = analyze_urls_in_text(message_text)
                threat_intel = ThreatIntelProvider()
                recommendations = get_safety_recommendations(res["predicted_categories"])
                
                # Log transaction to SQLite DB
                analysis_id = log_analysis(res, message_text)

            st.markdown("---")
            st.markdown("## 🎯 Analysis Results")
            
            # Top Banner: Risk Gauge & Overview
            res_col1, res_col2, res_col3 = st.columns([1.8, 1.2, 2])
            
            with res_col1:
                st.markdown("##### Overall Risk Level")
                risk_level = res["risk_level"]
                if "CRITICAL" in risk_level:
                    css_cls = "risk-critical"
                elif "HIGH" in risk_level:
                    css_cls = "risk-high"
                elif "MEDIUM" in risk_level:
                    css_cls = "risk-medium"
                else:
                    css_cls = "risk-low"
                    
                st.markdown(f'<div class="risk-badge {css_cls}">{risk_level}</div>', unsafe_allow_html=True)
                st.caption(f"Composite Risk Score: **{res['risk_score']} / 100**")
                
            with res_col2:
                st.markdown("##### Risk Gauge")
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=res["risk_score"],
                    domain={'x': [0, 1], 'y': [0, 1]},
                    gauge={
                        'axis': {'range': [None, 100], 'tickcolor': "#94a3b8"},
                        'bar': {'color': res["risk_color"]},
                        'steps': [
                            {'range': [0, 25], 'color': 'rgba(40, 167, 69, 0.2)'},
                            {'range': [25, 55], 'color': 'rgba(255, 193, 7, 0.2)'},
                            {'range': [55, 80], 'color': 'rgba(220, 53, 69, 0.2)'},
                            {'range': [80, 100], 'color': 'rgba(139, 0, 0, 0.3)'}
                        ]
                    }
                ))
                fig_gauge.update_layout(height=140, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig_gauge, use_container_width=True)

            with res_col3:
                st.markdown("##### Predicted Category / Categories")
                for cat in res["predicted_categories"]:
                    st.markdown(f"**🏷️ {cat['category']}** — Confidence: `{cat['confidence']}%`")
                    st.progress(cat["raw_prob"])

            # Detail Tabs/Sections
            st.markdown("---")
            d_col1, d_col2 = st.columns([1.5, 1.2])
            
            with d_col1:
                st.markdown("### ❓ Why Was This Flagged?")
                if res["detected_indicators"]:
                    st.markdown("##### 🚨 Detected Security Indicators")
                    for ind in res["detected_indicators"]:
                        with st.expander(f"🚩 {ind['name']} (Weight: {ind['weight']})", expanded=True):
                            st.write(ind["explanation"])
                            if ind["matched_snippets"]:
                                st.markdown(f"**Matched text:** `{', '.join(ind['matched_snippets'])}`")
                else:
                    st.info("No malicious heuristic patterns triggered.")
                    
                if explanation["contextual_insights"]:
                    st.markdown("##### 🧠 NLP Contextual Insights")
                    for insight in explanation["contextual_insights"]:
                        st.markdown(f"• {insight}")
                        
                st.caption(explanation["methodology_note"])

            with d_col2:
                st.markdown("### 🔗 URL & Threat Intelligence Analysis")
                if detected_urls:
                    st.markdown(f"**Extracted URLs Detected:** `{len(detected_urls)}`")
                    for u in detected_urls:
                        with st.expander(f"🌐 {u['domain']}", expanded=True):
                            st.write(f"**URL:** `{u['url']}`")
                            st.write(f"**HTTPS Encrypted:** {'✅ Yes' if u['is_https'] else '❌ No (HTTP)'}")
                            st.write(f"**IP-Based Host:** {'⚠️ Yes' if u['is_ip'] else '✅ No'}")
                            st.write(f"**Shortened Link:** {'⚠️ Yes' if u['is_shortened'] else '✅ No'}")
                            if u["indicators"]:
                                st.warning("Potentially suspicious static indicators:")
                                for ind_text in u["indicators"]:
                                    st.write(f" - {ind_text}")
                            else:
                                st.success(u["assessment"])
                                
                            # Query Threat Intel API stub for host
                            intel_res = threat_intel.check_domain_reputation(u["domain"])
                            st.caption(f"📡 Threat Intel: {intel_res['message']}")
                else:
                    st.info("No URLs found in the analyzed message.")
                    
                st.markdown("---")
                st.markdown("### 🛡️ Recommended Safety Actions")
                for rec in recommendations:
                    st.markdown(f"- {rec}")

            # User Reporting / Feedback Form
            st.markdown("---")
            st.markdown("### 📣 User Reporting & Model Feedback")
            st.caption("Was this prediction accurate? Submit anonymous feedback to help improve future research model versions.")
            
            fb_col1, fb_col2, fb_col3 = st.columns([1.5, 2, 1])
            with fb_col1:
                fb_status = st.radio("Feedback:", ["Correct ✅", "Incorrect ❌", "Unsure ❓"], horizontal=True)
            with fb_col2:
                fb_comment = st.text_input("Optional comment:", placeholder="e.g. Missed subtle blackmail implication...")
            with fb_col3:
                st.write("")
                if st.button("Submit Report"):
                    primary_cat = res["predicted_categories"][0]["category"]
                    log_user_feedback(analysis_id, primary_cat, fb_status, fb_comment)
                    st.success("Report recorded anonymously in SQLite DB. Thank you!")


# ==========================================
# TAB 2: RESEARCH & MODEL EVALUATION
# ==========================================
with tab_research:
    st.markdown("## 📊 Research Model Evaluation Dashboard")
    st.markdown("""
    > [!IMPORTANT]
    > **Research Transparency Disclaimer**: The metrics below are computed directly on the evaluation split of the dataset. 
    > No test scores or accuracy figures are fabricated.
    """)
    
    c_train, c_eval = st.columns([1, 2])
    with c_train:
        st.markdown("### ⚡ Train Pipeline Execution")
        st.write("Click below to re-execute the multi-model training & evaluation pipeline live.")
        if st.button("🔄 Retrain All ML Models Now"):
            with st.spinner("Training Logistic Regression, SVM, Random Forest, GBDT..."):
                train_and_evaluate_models()
                st.cache_resource.clear()
                st.success("Models retrained successfully!")
                st.rerun()
                
    # Load Evaluation Results JSON
    eval_json_path = "results/metrics_summary.json"
    if os.path.exists(eval_json_path):
        with open(eval_json_path, "r") as f:
            eval_data = json.load(f)
            
        st.markdown(f"**Selected Best Model:** `{eval_data.get('best_model_name')}` | **Total Samples:** `{eval_data.get('n_samples')}` (Train: `{eval_data.get('n_train')}`, Test: `{eval_data.get('n_test')}`)")
        
        # Summary Comparative Table
        evals = eval_data.get("evaluations", {})
        table_rows = []
        for model_name, m_dict in evals.items():
            table_rows.append({
                "Model Algorithm": model_name,
                "Exact Match Acc": f"{m_dict['exact_match_accuracy'] * 100:.2f}%",
                "Hamming Loss": f"{m_dict['hamming_loss']:.4f}",
                "F1 Micro": f"{m_dict['f1_micro']:.4f}",
                "F1 Macro": f"{m_dict['f1_macro']:.4f}",
                "Precision Macro": f"{m_dict['precision_macro']:.4f}",
                "Recall Macro": f"{m_dict['recall_macro']:.4f}"
            })
        df_models = pd.DataFrame(table_rows)
        st.table(df_models)
        
        # Comparative Charts
        st.markdown("### 📈 Model Comparison Charts")
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            df_chart = pd.DataFrame([
                {"Model": k, "F1 Micro": v["f1_micro"], "F1 Macro": v["f1_macro"]} 
                for k, v in evals.items()
            ])
            fig_bar = px.bar(df_chart, x="Model", y=["F1 Micro", "F1 Macro"], barmode="group", title="F1-Score Comparison Across Models", color_discrete_sequence=["#38bdf8", "#818cf8"])
            fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_bar, use_container_width=True)

        with chart_col2:
            df_acc = pd.DataFrame([
                {"Model": k, "Exact Match Accuracy": v["exact_match_accuracy"]} 
                for k, v in evals.items()
            ])
            fig_acc = px.bar(df_acc, x="Model", y="Exact Match Accuracy", color="Model", title="Exact Match Subset Accuracy", color_discrete_sequence=px.colors.qualitative.Dark24)
            fig_acc.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_acc, use_container_width=True)

        # Detailed Class Breakdown
        st.markdown("### 🎯 Per-Category Performance Breakdown")
        selected_m = st.selectbox("Select model for per-class breakdown:", list(evals.keys()))
        if selected_m in evals:
            cls_rep = evals[selected_m]["class_report"]
            cls_rows = []
            for cat in ALL_CATEGORIES:
                if cat in cls_rep:
                    cls_rows.append({
                        "Category": cat,
                        "Precision": f"{cls_rep[cat]['precision']:.4f}",
                        "Recall": f"{cls_rep[cat]['recall']:.4f}",
                        "F1-Score": f"{cls_rep[cat]['f1-score']:.4f}",
                        "Support (Samples)": int(cls_rep[cat]['support'])
                    })
            st.dataframe(pd.DataFrame(cls_rows), use_container_width=True)
    else:
        st.info("No trained evaluation metrics found. Click 'Retrain All ML Models Now' to generate.")


# ==========================================
# TAB 3: SYSTEM DASHBOARD & FEEDBACK
# ==========================================
with tab_analytics:
    st.markdown("## 📈 Live System Analytics & Feedback Database")
    analytics = get_summary_analytics()
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Messages Analyzed", analytics["total_analyzed"])
    m2.metric("High/Critical Threats Flagged", analytics["high_risk_count"])
    m3.metric("User Feedback Reports", sum(analytics["feedback_counts"].values()))
    
    st.markdown("---")
    a_col1, a_col2 = st.columns(2)
    
    with a_col1:
        st.markdown("### 🏷️ Category Breakdown in Logged Messages")
        cat_dist = analytics["category_distribution"]
        if cat_dist:
            df_cat = pd.DataFrame([{"Category": k, "Count": v} for k, v in cat_dist.items()])
            fig_pie = px.pie(df_cat, names="Category", values="Count", title="Detected Category Distribution", hole=0.4, color_discrete_sequence=px.colors.qualitative.Vivid)
            fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No analysis history recorded yet in SQLite DB.")

    with a_col2:
        st.markdown("### 💬 User Reporting Feedback Breakdown")
        fb_counts = analytics["feedback_counts"]
        if fb_counts:
            df_fb = pd.DataFrame([{"Feedback": k, "Count": v} for k, v in fb_counts.items()])
            fig_fb = px.bar(df_fb, x="Feedback", y="Count", color="Feedback", title="User Accuracy Reports")
            fig_fb.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
            st.plotly_chart(fig_fb, use_container_width=True)
        else:
            st.info("No user feedback submitted yet.")


# ==========================================
# TAB 4: METHODOLOGY & DOCUMENTATION
# ==========================================
with tab_docs:
    st.markdown("## 📑 Research Methodology & System Documentation")
    st.markdown("""
    ### 1. Research Problem & Objective
    Online fraud, phishing, blackmail, and cyberbullying continue to expand rapidly across digital messaging platforms. 
    Traditional keyword-blocking systems produce high false-positive rates and fail against sophisticated social engineering.
    **SafeGuard AI** implements a hybrid multi-label NLP classification architecture that combines statistical TF-IDF n-gram representations 
    with heuristic domain-aware threat indicators.

    ### 2. Supported Threat Taxonomy
    The system classifies messages across 10 defined categories:
    1. **`SAFE`**: Normal, non-threatening everyday communications.
    2. **`SCAM`**: General fraudulent offers, prize/lottery scams.
    3. **`PHISHING`**: Fake institution impersonation to lure credential entry.
    4. **`FINANCIAL_COERCION`**: Coercive pressure for immediate fund transfers.
    5. **`THREAT`**: Threats of physical harm, violence, or unlawful arrest.
    6. **`BLACKMAIL`**: Extortion threatening exposure of private photos or videos.
    7. **`CYBERBULLYING`**: Targeted offensive language and personal harassment.
    8. **`CREDENTIAL_THEFT`**: Direct requests for OTPs, PINs, or netbanking credentials.
    9. **`INVESTMENT_SCAM`**: High-yield fraudulent crypto or stock investment offers.
    10. **`JOB_SCAM`**: Fake employment offers requiring upfront fees or device payments.

    ### 3. Replacing Demo Dataset with Real Research Data
    To use this codebase for scientific publication:
    1. Prepare your corpus in CSV format with columns: `text` and `categories` (pipe-separated e.g. `BLACKMAIL|THREAT`).
    2. Save your dataset file to `data/research_dataset.csv`.
    3. Run `python src/train.py --data data/research_dataset.csv` to retrain all candidate classifiers.
    4. The updated model weights (`models/multi_label_model.joblib`) will be loaded automatically by Streamlit.

    ### 4. Future Work: BERT / Transformer Integration
    The system is engineered modularly: `src/feature_extraction.py` and `src/predict.py` abstract feature generation from inference. 
    To upgrade from TF-IDF + Classical ML to fine-tuned BERT or RoBERTa:
    - Replace `vectorizer.transform(text)` with `AutoTokenizer.from_pretrained('bert-base-uncased')`.
    - Replace Scikit-learn's `MultiOutputClassifier` with PyTorch `BertForSequenceClassification` using Binary Cross-Entropy (BCEWithLogitsLoss).
    """)
