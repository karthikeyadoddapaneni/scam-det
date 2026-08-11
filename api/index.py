"""
SafeGuard AI — Vercel Serverless Entry Point & Flask Web Interface
"""

import os
import sys
import json

# Ensure parent directory is in sys.path for Vercel execution environment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string

# Import SafeGuard AI modules
from src.predict import SafeguardPredictor
from src.explain import generate_explanation
from src.url_analyzer import analyze_urls_in_text
from src.reputation import ThreatIntelProvider
from src.recommendations import get_safety_recommendations
from src.database import log_analysis, log_user_feedback, get_summary_analytics

app = Flask(__name__)

# Initialize predictor singleton
try:
    predictor = SafeguardPredictor()
except Exception as e:
    print(f"Warning: Model initialization delayed: {e}")
    predictor = None

# Ephemeral database path for serverless environment
DB_PATH = "/tmp/safeguard_ai.db" if os.environ.get("VERCEL") else "safeguard_ai.db"


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeGuard AI — Cyber Safety & Scam Detection System</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0b0f19;
            --card-bg: #151c2c;
            --card-border: rgba(255, 255, 255, 0.08);
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-indigo: #6366f1;
            --accent-purple: #8b5cf6;
            --risk-low: #10b981;
            --risk-medium: #f59e0b;
            --risk-high: #ef4444;
            --risk-critical: #991b1b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            min-height: 100vh;
            line-height: 1.5;
            padding-bottom: 60px;
        }

        /* Header Banner */
        .header {
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 50%, #0284c7 100%);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 2.5rem 1.5rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: radial-gradient(circle at 50% -20%, rgba(6, 182, 212, 0.2), transparent 70%);
            pointer-events: none;
        }

        .header h1 {
            font-size: 2.4rem;
            font-weight: 800;
            background: linear-gradient(to right, #ffffff, #60a5fa, #38bdf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
        }

        .header p {
            color: #cbd5e1;
            font-size: 1.05rem;
            max-width: 700px;
            margin: 0 auto;
        }

        .badge-bar {
            display: flex;
            justify-content: center;
            gap: 12px;
            margin-top: 1rem;
            flex-wrap: wrap;
        }

        .badge {
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(255, 255, 255, 0.15);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            color: #93c5fd;
        }

        /* Container */
        .container {
            max-width: 1100px;
            margin: 2rem auto;
            padding: 0 1.5rem;
        }

        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }

        @media (max-width: 868px) {
            .grid-2 { grid-template-columns: 1fr; }
        }

        /* Card Component */
        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            margin-bottom: 1.5rem;
        }

        .card-header {
            font-size: 1.15rem;
            font-weight: 700;
            color: #f8fafc;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            padding-bottom: 0.75rem;
        }

        /* Textarea & Form */
        textarea {
            width: 100%;
            height: 160px;
            background: #090d16;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 12px;
            color: #f1f5f9;
            padding: 1rem;
            font-family: 'Inter', sans-serif;
            font-size: 0.95rem;
            resize: vertical;
            transition: all 0.2s ease;
        }

        textarea:focus {
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.2);
        }

        .presets {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin: 1rem 0;
        }

        .btn-preset {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-muted);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-preset:hover {
            background: rgba(6, 182, 212, 0.15);
            border-color: var(--accent-cyan);
            color: #38bdf8;
        }

        .btn-analyze {
            width: 100%;
            background: linear-gradient(135deg, var(--accent-cyan) 0%, var(--accent-blue) 100%);
            color: #ffffff;
            font-weight: 700;
            font-size: 1rem;
            padding: 14px;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            transition: transform 0.1s ease, box-shadow 0.2s ease;
            box-shadow: 0 4px 15px rgba(6, 182, 212, 0.3);
        }

        .btn-analyze:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(6, 182, 212, 0.4);
        }

        .btn-analyze:active {
            transform: translateY(0);
        }

        /* Results Display */
        .result-score-box {
            text-align: center;
            padding: 1.5rem;
            border-radius: 12px;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--card-border);
            margin-bottom: 1.25rem;
        }

        .score-number {
            font-size: 3.5rem;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            line-height: 1;
        }

        .score-label {
            font-size: 1rem;
            font-weight: 700;
            margin-top: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .progress-bg {
            height: 10px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 5px;
            overflow: hidden;
            margin-top: 1rem;
        }

        .progress-fill {
            height: 100%;
            border-radius: 5px;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }

        /* Category Pill */
        .cat-tag {
            display: inline-flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 8px 12px;
            border-radius: 8px;
            margin-bottom: 6px;
            width: 100%;
        }

        .indicator-item {
            background: rgba(239, 68, 68, 0.1);
            border-left: 4px solid var(--risk-high);
            padding: 10px 12px;
            border-radius: 0 8px 8px 0;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }

        .rec-item {
            background: rgba(59, 130, 246, 0.1);
            border-left: 4px solid var(--accent-blue);
            padding: 10px 12px;
            border-radius: 0 8px 8px 0;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }

        .url-box {
            background: #090d16;
            padding: 10px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            margin-bottom: 8px;
            border: 1px solid rgba(255,255,255,0.08);
        }

        .spinner {
            display: none;
            width: 24px;
            height: 24px;
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 0.8s ease-in-out infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 3rem;
        }

        .footer a {
            color: var(--accent-cyan);
            text-decoration: none;
        }
    </style>
</head>
<body>

    <header class="header">
        <h1>🛡️ SafeGuard AI</h1>
        <p>Cyber Safety & Multi-Category Scam Detection System</p>
        <div class="badge-bar">
            <span class="badge">Multi-Label ML Classifier</span>
            <span class="badge">Rule-Based Heuristic Engine</span>
            <span class="badge">Threat Intel & URL Analyzer</span>
            <span class="badge">Vercel Serverless Ready</span>
        </div>
    </header>

    <div class="container">
        <div class="grid-2">
            <!-- Left Panel: Input & Controls -->
            <div>
                <div class="card">
                    <div class="card-header">
                        💬 Analyze Suspicious Content
                    </div>
                    <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
                        Paste any suspicious SMS, email, WhatsApp message, link, or blackmail text below:
                    </p>
                    
                    <textarea id="inputText" placeholder="e.g., URGENT: Your bank account #9283 is blocked. Verify immediately at http://secure-bank-login.xyz or your funds will be frozen."></textarea>
                    
                    <div class="presets">
                        <span style="font-size: 0.8rem; color: var(--text-muted); align-self: center;">Presets:</span>
                        <button class="btn-preset" onclick="loadPreset('phishing')">Phishing SMS</button>
                        <button class="btn-preset" onclick="loadPreset('blackmail')">Blackmail Threat</button>
                        <button class="btn-preset" onclick="loadPreset('job')">Job Scam</button>
                        <button class="btn-preset" onclick="loadPreset('investment')">Crypto/Lottery</button>
                        <button class="btn-preset" onclick="loadPreset('safe')">Safe Email</button>
                    </div>

                    <button class="btn-analyze" onclick="analyzeText()">
                        <span id="btnText">🛡️ Run Threat Analysis</span>
                        <div class="spinner" id="spinner"></div>
                    </button>
                </div>

                <div class="card">
                    <div class="card-header">
                        ℹ️ Supported Threat Categories
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.85rem; color: var(--text-muted);">
                        <div>• Phishing & Credentials</div>
                        <div>• Financial Coercion</div>
                        <div>• Blackmail & Extortion</div>
                        <div>• Investment & Crypto Scams</div>
                        <div>• Job & Part-time Scams</div>
                        <div>• Violent / Physical Threats</div>
                        <div>• Cyberbullying & Abuse</div>
                        <div>• Bank Impersonation</div>
                    </div>
                </div>
            </div>

            <!-- Right Panel: Dynamic Results -->
            <div>
                <div class="card" id="resultsCard" style="display: none;">
                    <div class="card-header">
                        📊 Threat Assessment Results
                    </div>
                    
                    <!-- Score Box -->
                    <div class="result-score-box" id="scoreBox">
                        <div class="score-number" id="riskScore">0</div>
                        <div class="score-label" id="riskLevel">LOW RISK</div>
                        <div class="progress-bg">
                            <div class="progress-fill" id="progressFill"></div>
                        </div>
                    </div>

                    <!-- Categories -->
                    <div style="margin-bottom: 1.25rem;">
                        <h4 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: #cbd5e1;">Detected Threat Categories</h4>
                        <div id="categoriesList"></div>
                    </div>

                    <!-- Explanation -->
                    <div style="margin-bottom: 1.25rem;">
                        <h4 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: #cbd5e1;">AI Safety Explanation</h4>
                        <div style="background: #090d16; padding: 12px; border-radius: 8px; font-size: 0.9rem; border: 1px solid rgba(255,255,255,0.08);" id="explanationText"></div>
                    </div>

                    <!-- Heuristic Indicators -->
                    <div style="margin-bottom: 1.25rem;" id="indicatorsSection">
                        <h4 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: #cbd5e1;">Flagged Indicators</h4>
                        <div id="indicatorsList"></div>
                    </div>

                    <!-- URL Analysis -->
                    <div style="margin-bottom: 1.25rem;" id="urlSection">
                        <h4 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: #cbd5e1;">Embedded Link Inspection</h4>
                        <div id="urlList"></div>
                    </div>

                    <!-- Recommendations -->
                    <div>
                        <h4 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: #cbd5e1;">Actionable Safety Advice</h4>
                        <div id="recList"></div>
                    </div>
                </div>

                <!-- Initial Placeholder Card -->
                <div class="card" id="placeholderCard">
                    <div style="text-align: center; padding: 3rem 1rem; color: var(--text-muted);">
                        <div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>
                        <h3>No Analysis Conducted Yet</h3>
                        <p style="font-size: 0.9rem; margin-top: 0.5rem;">
                            Enter suspicious text on the left and click <b>Run Threat Analysis</b> to view multi-label predictions, heuristic triggers, link safety, and recommendations.
                        </p>
                    </div>
                </div>
            </div>
        </div>

        <footer class="footer">
            SafeGuard AI System &copy; 2026. Built with Python & Flask. Deployed on <b>Vercel Serverless</b>.
        </footer>
    </div>

    <script>
        const PRESETS = {
            phishing: "URGENT: Your HDFC bank account is suspended due to missing KYC. Click http://hdfc-update-kyc.net to enter your OTP & card details now or account will be permanently closed.",
            blackmail: "I have recorded video of you browsing adult websites. Pay 0.05 BTC to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 24 hours or I will leak this video to all your Facebook contacts.",
            job: "Congratulations! You are selected for online Telegram rating job. Earn ₹5,000 per day by just liking YouTube videos. Pay registration fee ₹1,500 to start.",
            investment: "Guaranteed 300% profit in 24 hours! Join our exclusive Crypto Telegram signal channel. Deposit ₹10,000 to double your money immediately.",
            safe: "Hi Karthik, here is the updated project documentation and design slides for tomorrow's review meeting. Let me know if you have any feedback!"
        };

        function loadPreset(key) {
            document.getElementById('inputText').value = PRESETS[key] || '';
        }

        async function analyzeText() {
            const text = document.getElementById('inputText').value.trim();
            if (!text) {
                alert('Please enter some text to analyze.');
                return;
            }

            const btnText = document.getElementById('btnText');
            const spinner = document.getElementById('spinner');
            btnText.style.display = 'none';
            spinner.style.display = 'block';

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text })
                });
                
                const data = await response.json();

                if (data.status === 'success') {
                    renderResults(data.result);
                } else {
                    alert('Error analyzing content: ' + (data.message || 'Unknown error'));
                }
            } catch (err) {
                console.error(err);
                alert('Network error communicating with SafeGuard AI backend.');
            } finally {
                btnText.style.display = 'inline';
                spinner.style.display = 'none';
            }
        }

        function renderResults(res) {
            document.getElementById('placeholderCard').style.display = 'none';
            const card = document.getElementById('resultsCard');
            card.style.display = 'block';

            // Risk Score
            const scoreEl = document.getElementById('riskScore');
            const levelEl = document.getElementById('riskLevel');
            const fillEl = document.getElementById('progressFill');

            scoreEl.innerText = res.risk_score;
            scoreEl.style.color = res.risk_color;
            levelEl.innerText = res.risk_level;
            levelEl.style.color = res.risk_color;

            fillEl.style.width = res.risk_score + '%';
            fillEl.style.backgroundColor = res.risk_color;

            // Categories
            const catList = document.getElementById('categoriesList');
            catList.innerHTML = res.predicted_categories.map(c => `
                <div class="cat-tag">
                    <span style="font-weight:600;">${c.category}</span>
                    <span style="color:var(--accent-cyan); font-family:'JetBrains Mono', monospace; font-size:0.85rem;">${c.confidence}% Confidence</span>
                </div>
            `).join('');

            // Explanation
            document.getElementById('explanationText').innerText = res.explanation || 'No detailed explanation generated.';

            // Indicators
            const indSection = document.getElementById('indicatorsSection');
            const indList = document.getElementById('indicatorsList');
            if (res.detected_indicators && res.detected_indicators.length > 0) {
                indSection.style.display = 'block';
                indList.innerHTML = res.detected_indicators.map(ind => `
                    <div class="indicator-item">
                        <b>${ind.name}</b>: ${ind.description}
                    </div>
                `).join('');
            } else {
                indSection.style.display = 'none';
            }

            // URLs
            const urlSection = document.getElementById('urlSection');
            const urlList = document.getElementById('urlList');
            if (res.url_analysis && res.url_analysis.length > 0) {
                urlSection.style.display = 'block';
                urlList.innerHTML = res.url_analysis.map(u => `
                    <div class="url-box">
                        <div><b>URL:</b> ${u.url}</div>
                        <div style="color:${u.suspicious ? '#ef4444' : '#10b981'}; margin-top:4px;">
                            ${u.suspicious ? '⚠️ Suspicious Domain Detected' : '✅ Standard Domain'} 
                            ${u.reasons ? `(${u.reasons.join(', ')})` : ''}
                        </div>
                    </div>
                `).join('');
            } else {
                urlSection.style.display = 'none';
            }

            // Recommendations
            const recList = document.getElementById('recList');
            recList.innerHTML = (res.recommendations || []).map(r => `
                <div class="rec-item">${r}</div>
            `).join('');
        }
    </script>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def home():
    """Renders SafeGuard AI web interface."""
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/health", methods=["GET"])
def health():
    """API health status endpoint."""
    return jsonify({
        "status": "online",
        "system": "SafeGuard AI",
        "deployment": "Vercel Serverless",
        "version": "1.0.0"
    })


@app.route("/api/analyze", methods=["POST"])
def analyze_endpoint():
    """Main analysis REST endpoint."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        text = data.get("text", "").strip()

        if not text:
            return jsonify({
                "status": "error",
                "message": "Field 'text' is required."
            }), 400

        global predictor
        if predictor is None:
            predictor = SafeguardPredictor()

        # 1. Core Threat Prediction
        result = predictor.predict(text)

        # 2. URL Inspection & Threat Intelligence
        url_results = analyze_urls_in_text(text)
        threat_intel = ThreatIntelProvider()

        # Check reputation for embedded URLs
        for url_info in url_results:
            rep = threat_intel.check_url_reputation(url_info["url"])
            url_info["threat_reputation"] = rep

        result["url_analysis"] = url_results

        # 3. Actionable Recommendations
        recs = get_safety_recommendations(result["predicted_categories"], url_results)
        result["recommendations"] = recs

        # 4. Natural Language Explanation
        explanation = generate_explanation(result)
        result["explanation"] = explanation

        # 5. Log transaction silently to database if permissible
        try:
            analysis_id = log_analysis(result, text, db_path=DB_PATH)
            result["analysis_id"] = analysis_id
        except Exception as log_err:
            print(f"Non-fatal logging warning: {log_err}")
            result["analysis_id"] = None

        return jsonify({
            "status": "success",
            "result": result
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/api/feedback", methods=["POST"])
def feedback_endpoint():
    """Logs user feedback for continuous improvement."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        analysis_id = data.get("analysis_id")
        predicted_cat = data.get("predicted_category", "UNKNOWN")
        status = data.get("feedback_status", "CONFIRMED")
        comment = data.get("user_comment", "")

        log_user_feedback(analysis_id, predicted_cat, status, comment, db_path=DB_PATH)

        return jsonify({
            "status": "success",
            "message": "Feedback recorded."
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
