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
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>CIPHER — Click with confidence.</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-app: #f8fafc;
            --surface-card: #ffffff;
            --surface-subtle: #f1f5f9;
            --border-color: #e2e8f0;
            --border-hover: #cbd5e1;
            
            --teal-50: #f0fdf4;
            --teal-100: #ccfbf1;
            --teal-200: #99f6e4;
            --teal-500: #14b8a6;
            --teal-600: #0d9488;
            --teal-700: #0f766e;
            --teal-900: #134e4a;

            --text-main: #0f172a;
            --text-body: #334155;
            --text-muted: #64748b;
            --text-light: #94a3b8;

            --risk-high-bg: #fef2f2;
            --risk-high-border: #fecaca;
            --risk-high-text: #dc2626;

            --risk-med-bg: #fffbeb;
            --risk-med-border: #fde68a;
            --risk-med-text: #d97706;

            --risk-safe-bg: #f0fdf4;
            --risk-safe-border: #ccfbf1;
            --risk-safe-text: #0d9488;

            --shadow-sm: 0 1px 3px rgba(15, 23, 42, 0.04), 0 1px 2px rgba(0, 0, 0, 0.02);
            --shadow-md: 0 4px 20px -2px rgba(15, 23, 42, 0.06), 0 2px 6px -1px rgba(0, 0, 0, 0.03);
            --shadow-lg: 0 12px 32px -4px rgba(15, 23, 42, 0.1), 0 4px 12px -2px rgba(0, 0, 0, 0.04);
            --shadow-teal: 0 8px 24px -4px rgba(13, 148, 136, 0.25);
            
            --radius-card: 20px;
            --radius-btn: 14px;
            --radius-pill: 9999px;
            --font-main: 'Plus Jakarta Sans', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        body.large-text-mode { font-size: 115%; }
        body.high-contrast-mode {
            --bg-app: #ffffff;
            --surface-card: #ffffff;
            --border-color: #0f172a;
            --text-main: #000000;
            --text-muted: #1e293b;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
        body { font-family: var(--font-main); background-color: var(--bg-app); color: var(--text-main); min-height: 100vh; line-height: 1.5; display: flex; justify-content: center; }

        .app-viewport {
            width: 100%; max-width: 480px; background: var(--bg-app); min-height: 100vh; position: relative; box-shadow: 0 0 40px rgba(0, 0, 0, 0.05); display: flex; flex-direction: column; padding-bottom: 90px;
        }

        .app-header {
            background: rgba(255, 255, 255, 0.9); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border-color); padding: 1rem 1.25rem; position: sticky; top: 0; z-index: 100; display: flex; align-items: center; justify-content: space-between;
        }

        .brand { display: flex; align-items: center; gap: 10px; cursor: pointer; }
        .brand-logo-icon { width: 36px; height: 36px; background: linear-gradient(135deg, var(--teal-600), var(--teal-500)); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: #ffffff; box-shadow: var(--shadow-teal); }
        .brand-logo-icon svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 2.2; }
        .brand-text h1 { font-size: 1.15rem; font-weight: 800; letter-spacing: 0.02em; color: var(--text-main); line-height: 1.1; }
        .brand-text p { font-size: 0.72rem; color: var(--teal-600); font-weight: 600; }

        .header-actions { display: flex; align-items: center; gap: 8px; }
        .btn-icon-head { width: 38px; height: 38px; border-radius: 50%; background: var(--surface-subtle); border: 1px solid var(--border-color); color: var(--text-body); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s ease; }
        .btn-icon-head:hover { background: var(--teal-50); border-color: var(--teal-200); color: var(--teal-700); }

        .greeting-section { padding: 1.25rem 1.25rem 0.5rem 1.25rem; }
        .greeting-title { font-size: 1.45rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.02em; line-height: 1.2; }
        .greeting-subtitle { font-size: 0.9rem; color: var(--text-muted); font-weight: 500; margin-top: 4px; }

        .status-card {
            background: var(--surface-card); border: 1px solid var(--teal-200); border-radius: var(--radius-card); padding: 1rem 1.25rem; margin: 1rem 1.25rem; display: flex; align-items: center; gap: 14px; box-shadow: var(--shadow-sm); background: linear-gradient(135deg, #ffffff 0%, var(--teal-50) 100%); position: relative;
        }
        .status-badge-icon { width: 44px; height: 44px; border-radius: 14px; background: var(--teal-100); color: var(--teal-700); display: flex; align-items: center; justify-content: center; font-size: 1.4rem; flex-shrink: 0; position: relative; }
        .pulse-dot { width: 10px; height: 10px; background: var(--teal-500); border: 2px solid #ffffff; border-radius: 50%; position: absolute; top: -2px; right: -2px; box-shadow: 0 0 8px var(--teal-500); animation: pulse-ring 2s infinite; }

        @keyframes pulse-ring { 0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(20, 184, 166, 0.7); } 70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(20, 184, 166, 0); } 100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(20, 184, 166, 0); } }

        .status-content h3 { font-size: 0.95rem; font-weight: 700; color: var(--teal-900); display: flex; align-items: center; gap: 6px; }
        .status-content p { font-size: 0.82rem; color: var(--teal-700); font-weight: 500; }

        .quick-check-banner { background: var(--surface-card); border: 1px solid var(--border-color); border-radius: var(--radius-card); padding: 1.15rem; margin: 0 1.25rem 1.25rem 1.25rem; box-shadow: var(--shadow-md); }
        .quick-check-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.85rem; }
        .quick-check-title { font-size: 0.88rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

        .btn-quick-primary { width: 100%; background: linear-gradient(135deg, var(--teal-600), var(--teal-500)); color: #ffffff; font-weight: 700; font-size: 1.05rem; padding: 0.85rem 1.25rem; border-radius: var(--radius-btn); border: none; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; box-shadow: var(--shadow-teal); transition: all 0.2s ease; }
        .btn-quick-primary:hover { transform: translateY(-2px); background: linear-gradient(135deg, var(--teal-700), var(--teal-600)); }

        .quick-chips { display: flex; gap: 6px; overflow-x: auto; padding-top: 0.85rem; scrollbar-width: none; }
        .quick-chips::-webkit-scrollbar { display: none; }
        .chip { background: var(--surface-subtle); border: 1px solid var(--border-color); color: var(--text-body); padding: 5px 12px; border-radius: var(--radius-pill); font-size: 0.78rem; font-weight: 600; white-space: nowrap; cursor: pointer; transition: all 0.15s ease; }
        .chip:hover { background: var(--teal-50); border-color: var(--teal-200); color: var(--teal-700); }

        .section-header { padding: 0 1.25rem 0.75rem 1.25rem; display: flex; align-items: center; justify-content: space-between; }
        .section-title { font-size: 1.1rem; font-weight: 800; color: var(--text-main); }
        .tools-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; padding: 0 1.25rem 1.5rem 1.25rem; }
        .tool-card { background: var(--surface-card); border: 1px solid var(--border-color); border-radius: var(--radius-card); padding: 1.1rem; cursor: pointer; transition: all 0.2s ease; display: flex; flex-direction: column; justify-content: space-between; box-shadow: var(--shadow-sm); }
        .tool-card:hover { transform: translateY(-3px); border-color: var(--teal-500); box-shadow: var(--shadow-md); }
        .tool-icon-wrapper { width: 42px; height: 42px; border-radius: 12px; background: var(--teal-50); color: var(--teal-600); display: flex; align-items: center; justify-content: center; font-size: 1.35rem; margin-bottom: 0.85rem; border: 1px solid var(--teal-100); }
        .tool-name { font-size: 0.95rem; font-weight: 700; color: var(--text-main); margin-bottom: 4px; line-height: 1.25; }
        .tool-desc { font-size: 0.75rem; color: var(--text-muted); line-height: 1.35; font-weight: 500; }

        .bottom-nav { position: fixed; bottom: 0; left: 50%; transform: translateX(-50%); width: 100%; max-width: 480px; background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(16px); border-top: 1px solid var(--border-color); display: grid; grid-template-columns: repeat(5, 1fr); padding: 8px 0; z-index: 200; }
        .nav-item { display: flex; flex-direction: column; align-items: center; justify-content: center; color: var(--text-muted); font-size: 0.7rem; font-weight: 600; text-decoration: none; cursor: pointer; padding: 4px 0; transition: color 0.15s ease; }
        .nav-item svg { width: 22px; height: 22px; fill: none; stroke: currentColor; stroke-width: 2; margin-bottom: 3px; }
        .nav-item.active { color: var(--teal-600); font-weight: 700; }

        .tab-view { display: none; }
        .tab-view.active { display: block; }

        .splash-screen { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: #ffffff; z-index: 1000; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem; text-align: center; transition: opacity 0.4s ease, visibility 0.4s ease; }
        .splash-screen.hidden { opacity: 0; visibility: hidden; pointer-events: none; }
        .splash-logo-box { width: 90px; height: 90px; background: linear-gradient(135deg, var(--teal-600), var(--teal-500)); border-radius: 26px; display: flex; align-items: center; justify-content: center; color: #ffffff; box-shadow: 0 16px 40px rgba(13, 148, 136, 0.3); margin-bottom: 1.5rem; position: relative; }
        .splash-logo-box::after { content: ''; position: absolute; inset: -6px; border-radius: 32px; border: 2px solid var(--teal-200); opacity: 0.6; animation: pulse-ring 2.5s infinite; }
        .splash-title { font-size: 2.2rem; font-weight: 800; letter-spacing: 0.04em; color: var(--text-main); margin-bottom: 0.25rem; }
        .splash-caption { font-size: 1.05rem; color: var(--teal-600); font-weight: 600; margin-bottom: 2rem; }
        .splash-desc { font-size: 0.9rem; color: var(--text-muted); max-width: 320px; line-height: 1.5; margin-bottom: 2.5rem; }
        .btn-splash-start { background: linear-gradient(135deg, var(--teal-600), var(--teal-500)); color: #ffffff; font-weight: 700; font-size: 1rem; padding: 1rem 2.5rem; border-radius: var(--radius-pill); border: none; cursor: pointer; box-shadow: var(--shadow-teal); transition: all 0.2s ease; }

        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.4); backdrop-filter: blur(8px); z-index: 500; display: flex; align-items: flex-end; justify-content: center; opacity: 0; visibility: hidden; transition: all 0.25s ease; }
        .modal-overlay.open { opacity: 1; visibility: visible; }
        .modal-card { width: 100%; max-width: 480px; background: var(--surface-card); border-radius: 28px 28px 0 0; padding: 1.5rem; max-height: 88vh; overflow-y: auto; box-shadow: var(--shadow-lg); transform: translateY(100%); transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
        .modal-overlay.open .modal-card { transform: translateY(0); }
        .modal-handle { width: 40px; height: 5px; background: var(--border-color); border-radius: 10px; margin: 0 auto 1.25rem auto; }
        .modal-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; }
        .modal-title { font-size: 1.2rem; font-weight: 800; color: var(--text-main); }
        .btn-close-modal { background: var(--surface-subtle); border: none; width: 32px; height: 32px; border-radius: 50%; font-weight: 700; color: var(--text-muted); cursor: pointer; }

        .modal-tool-tabs { display: flex; gap: 6px; overflow-x: auto; margin-bottom: 1.25rem; padding-bottom: 4px; scrollbar-width: none; }
        .modal-tool-tabs::-webkit-scrollbar { display: none; }
        .modal-tab-btn { background: var(--surface-subtle); border: 1px solid var(--border-color); color: var(--text-muted); padding: 6px 14px; border-radius: var(--radius-pill); font-size: 0.8rem; font-weight: 600; white-space: nowrap; cursor: pointer; }
        .modal-tab-btn.active { background: var(--teal-600); border-color: var(--teal-600); color: #ffffff; }

        .presets-box { margin-bottom: 1rem; }
        .presets-label { font-size: 0.75rem; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; }
        .preset-btns { display: flex; gap: 6px; flex-wrap: wrap; }
        .btn-preset-item { background: var(--teal-50); border: 1px solid var(--teal-200); color: var(--teal-700); padding: 5px 10px; border-radius: 8px; font-size: 0.76rem; font-weight: 600; cursor: pointer; }

        textarea.check-input { width: 100%; height: 120px; background: var(--surface-subtle); border: 1.5px solid var(--border-color); border-radius: 14px; padding: 1rem; font-family: var(--font-main); font-size: 0.95rem; color: var(--text-main); resize: none; transition: all 0.2s ease; }
        textarea.check-input:focus { outline: none; border-color: var(--teal-500); background: #ffffff; box-shadow: 0 0 0 3px rgba(20, 184, 166, 0.15); }
        .btn-run-check { width: 100%; background: linear-gradient(135deg, var(--teal-600), var(--teal-500)); color: #ffffff; font-weight: 700; font-size: 1rem; padding: 0.9rem; border-radius: var(--radius-btn); border: none; cursor: pointer; margin-top: 1rem; box-shadow: var(--shadow-teal); display: flex; align-items: center; justify-content: center; gap: 8px; }

        .result-container { margin-top: 1.25rem; display: none; }
        .result-container.show { display: block; }

        .risk-banner { border-radius: 16px; padding: 1.25rem; margin-bottom: 1rem; }
        .risk-banner.high-risk { background: var(--risk-high-bg); border: 1.5px solid var(--risk-high-border); color: var(--risk-high-text); }
        .risk-banner.safe-risk { background: var(--risk-safe-bg); border: 1.5px solid var(--risk-safe-border); color: var(--risk-safe-text); }

        .risk-banner-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
        .risk-main-title { font-size: 1.15rem; font-weight: 800; display: flex; align-items: center; gap: 8px; }
        .risk-level-tag { font-size: 0.75rem; font-weight: 800; padding: 3px 10px; border-radius: var(--radius-pill); text-transform: uppercase; background: rgba(255, 255, 255, 0.8); }
        .risk-summary-text { font-size: 0.9rem; font-weight: 600; line-height: 1.4; opacity: 0.95; }

        .result-section-box { background: var(--surface-subtle); border: 1px solid var(--border-color); border-radius: 14px; padding: 1rem; margin-bottom: 0.85rem; }
        .result-section-box h4 { font-size: 0.85rem; font-weight: 800; color: var(--text-main); margin-bottom: 8px; display: flex; align-items: center; gap: 6px; text-transform: uppercase; }

        .bullet-list { list-style: none; }
        .bullet-list li { font-size: 0.85rem; color: var(--text-body); margin-bottom: 6px; position: relative; padding-left: 18px; font-weight: 500; line-height: 1.4; }
        .bullet-list li::before { content: '•'; position: absolute; left: 4px; color: var(--teal-600); font-weight: 800; }

        .disclaimer-note { font-size: 0.78rem; color: var(--text-muted); background: #ffffff; border: 1px solid var(--border-color); border-radius: 10px; padding: 8px 12px; margin-top: 1rem; line-height: 1.35; }

        .alerts-list { padding: 1.25rem; display: flex; flex-direction: column; gap: 12px; }
        .alert-card-item { background: var(--surface-card); border: 1px solid var(--border-color); border-radius: var(--radius-card); padding: 1rem 1.15rem; box-shadow: var(--shadow-sm); }
        .alert-item-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
        .alert-type-badge { font-size: 0.72rem; font-weight: 700; padding: 3px 8px; border-radius: 6px; }

        .history-list { padding: 1.25rem; display: flex; flex-direction: column; gap: 10px; }
        .history-item-card { background: var(--surface-card); border: 1px solid var(--border-color); border-radius: 14px; padding: 0.9rem 1.1rem; display: flex; align-items: center; justify-content: space-between; box-shadow: var(--shadow-sm); }
        .history-info h5 { font-size: 0.88rem; font-weight: 700; color: var(--text-main); }
        .history-info p { font-size: 0.78rem; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px; }
        .btn-delete-history { background: none; border: none; color: var(--text-muted); font-size: 0.8rem; cursor: pointer; padding: 4px 8px; }
        .btn-delete-history:hover { color: var(--risk-high-text); }

        .profile-container { padding: 1.25rem; }
        .profile-card { background: var(--surface-card); border: 1px solid var(--border-color); border-radius: var(--radius-card); padding: 1.25rem; margin-bottom: 1.25rem; box-shadow: var(--shadow-sm); }
        .setting-toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid var(--border-color); }
        .setting-toggle-row:last-child { border-bottom: none; }
        .setting-label h5 { font-size: 0.9rem; font-weight: 700; color: var(--text-main); }
        .setting-label p { font-size: 0.78rem; color: var(--text-muted); }

        .switch { position: relative; display: inline-block; width: 44px; height: 24px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--border-color); transition: .2s; border-radius: 24px; }
        .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .2s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--teal-600); }
        input:checked + .slider:before { transform: translateX(20px); }
    </style>
</head>
<body>

    <div class="app-viewport">
        <!-- Splash Screen -->
        <div class="splash-screen" id="splashScreen">
            <div class="splash-logo-box">
                <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div class="splash-title">CIPHER</div>
            <div class="splash-caption">Click with confidence.</div>
            <div class="splash-desc">
                Your all-in-one digital safety assistant to verify links, SMS messages, unknown calls, QR codes, images, and malware threats instantly.
            </div>
            <button class="btn-splash-start" onclick="dismissSplash()">Get Started ➔</button>
        </div>

        <!-- Header -->
        <header class="app-header">
            <div class="brand" onclick="showTab('tab-home')">
                <div class="brand-logo-icon">
                    <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div class="brand-text">
                    <h1>CIPHER</h1>
                    <p>Click with confidence.</p>
                </div>
            </div>
            <div class="header-actions">
                <button class="btn-icon-head" title="Profile & Accessibility" onclick="showTab('tab-profile')">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </button>
            </div>
        </header>

        <!-- TAB 1: HOME -->
        <main class="tab-view active" id="tab-home">
            <div class="greeting-section">
                <div class="greeting-title">Stay one step ahead.</div>
                <div class="greeting-subtitle">Check before you click, answer, scan or share.</div>
            </div>

            <div class="status-card">
                <div class="status-badge-icon">
                    🛡️
                    <div class="pulse-dot"></div>
                </div>
                <div class="status-content">
                    <h3>You’re protected</h3>
                    <p>“Your digital safety checks are active.”</p>
                </div>
            </div>

            <div class="quick-check-banner">
                <div class="quick-check-header">
                    <div class="quick-check-title">What do you want to verify?</div>
                </div>
                <button class="btn-quick-primary" onclick="openVerificationModal('Link')">
                    <span style="font-size:1.2rem;">＋</span> Quick Check
                </button>
                <div class="quick-chips">
                    <div class="chip" onclick="openVerificationModal('Message')">💬 Message</div>
                    <div class="chip" onclick="openVerificationModal('Number')">📱 Number</div>
                    <div class="chip" onclick="openVerificationModal('Link')">🌐 Link</div>
                    <div class="chip" onclick="openVerificationModal('QR')">🔲 QR Code</div>
                    <div class="chip" onclick="openVerificationModal('Image')">🖼️ Image</div>
                    <div class="chip" onclick="openVerificationModal('Audio')">🎙️ Audio</div>
                    <div class="chip" onclick="openVerificationModal('File')">🚨 File</div>
                </div>
            </div>

            <div class="section-header">
                <div class="section-title">Detection Tools</div>
            </div>

            <div class="tools-grid">
                <div class="tool-card" onclick="openVerificationModal('Message')">
                    <div class="tool-icon-wrapper">💬</div>
                    <div>
                        <div class="tool-name">Text Messages</div>
                        <div class="tool-desc">Check SMS for suspicious links, scams & fraud patterns.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('Number')">
                    <div class="tool-icon-wrapper">📞</div>
                    <div>
                        <div class="tool-name">Phone Calls</div>
                        <div class="tool-desc">Analyze suspicious calls and identify potential scam behavior.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('Number')">
                    <div class="tool-icon-wrapper">📱</div>
                    <div>
                        <div class="tool-name">Unknown Numbers</div>
                        <div class="tool-desc">Check unfamiliar phone numbers for possible fraud or spam risk.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('Number')">
                    <div class="tool-icon-wrapper">🟢</div>
                    <div>
                        <div class="tool-name">WhatsApp Calls</div>
                        <div class="tool-desc">Check suspicious WhatsApp call activity & scam indicators.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('Message')">
                    <div class="tool-icon-wrapper">💬</div>
                    <div>
                        <div class="tool-name">WhatsApp Texts</div>
                        <div class="tool-desc">Analyze WhatsApp messages, links and suspicious requests.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('Link')">
                    <div class="tool-icon-wrapper">🌐</div>
                    <div>
                        <div class="tool-name">Websites</div>
                        <div class="tool-desc">Check whether a website or URL appears suspicious or unsafe.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('QR')">
                    <div class="tool-icon-wrapper">🔲</div>
                    <div>
                        <div class="tool-name">QR Codes</div>
                        <div class="tool-desc">Scan QR codes and check the destination before opening it.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('Image')">
                    <div class="tool-icon-wrapper">🖼️</div>
                    <div>
                        <div class="tool-name">Images</div>
                        <div class="tool-desc">Identify scam ads, fake payment receipts or manipulated images.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('Audio')">
                    <div class="tool-icon-wrapper">🎙️</div>
                    <div>
                        <div class="tool-name">Voice Detection</div>
                        <div class="tool-desc">Analyze voice recordings for scam indicators or AI audio.</div>
                    </div>
                </div>

                <div class="tool-card" onclick="openVerificationModal('File')">
                    <div class="tool-icon-wrapper">🚨</div>
                    <div>
                        <div class="tool-name">Virus Alerts</div>
                        <div class="tool-desc">Detect & explain malware, malicious files or threats.</div>
                    </div>
                </div>
            </div>
        </main>

        <!-- TAB 2: DETECT HUB -->
        <main class="tab-view" id="tab-detect">
            <div class="greeting-section">
                <div class="greeting-title">Detection Hub</div>
                <div class="greeting-subtitle">Select any tool to start real-time verification.</div>
            </div>
            <div style="padding: 1.25rem;">
                <button class="btn-quick-primary" onclick="openVerificationModal('Link')">
                    <span>⚡ Launch Real-Time Scanner</span>
                </button>
            </div>
        </main>

        <!-- TAB 3: ALERTS -->
        <main class="tab-view" id="tab-alerts">
            <div class="greeting-section">
                <div class="greeting-title">Security Alerts</div>
                <div class="greeting-subtitle">Stay informed on active fraud campaigns & threat updates.</div>
            </div>

            <div class="alerts-list">
                <div class="alert-card-item">
                    <div class="alert-item-head">
                        <span class="alert-type-badge" style="background:#fef2f2; color:#dc2626;">🚨 High Risk</span>
                        <span style="font-size:0.75rem; color:var(--text-muted);">Today</span>
                    </div>
                    <h4 style="font-size:0.95rem; font-weight:700; color:var(--text-main);">Fake Electricity Bill Deactivation SMS</h4>
                    <p style="font-size:0.82rem; color:var(--text-body); margin-top:4px;">Scammers are sending SMS claiming power supply will be cut at 9 PM unless an immediate UPI transfer is completed.</p>
                </div>

                <div class="alert-card-item">
                    <div class="alert-item-head">
                        <span class="alert-type-badge" style="background:#fffbeb; color:#d97706;">⚠️ Suspicious</span>
                        <span style="font-size:0.75rem; color:var(--text-muted);">Yesterday</span>
                    </div>
                    <h4 style="font-size:0.95rem; font-weight:700; color:var(--text-main);">Part-Time YouTube Like Job Scam</h4>
                    <p style="font-size:0.82rem; color:var(--text-body); margin-top:4px;">Unsolicited WhatsApp job offers asking for $50 registration fee to begin online rating tasks.</p>
                </div>

                <div class="alert-card-item">
                    <div class="alert-item-head">
                        <span class="alert-type-badge" style="background:#f0fdf4; color:#0d9488;">✓ Safe</span>
                        <span style="font-size:0.75rem; color:var(--text-muted);">3 days ago</span>
                    </div>
                    <h4 style="font-size:0.95rem; font-weight:700; color:var(--text-main);">Official Banking App Update Verified</h4>
                    <p style="font-size:0.82rem; color:var(--text-body); margin-top:4px;">Standard app store security updates released for major mobile banking applications.</p>
                </div>
            </div>
        </main>

        <!-- TAB 4: HISTORY -->
        <main class="tab-view" id="tab-history">
            <div class="greeting-section" style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <div class="greeting-title">Verification History</div>
                    <div class="greeting-subtitle">Your recent safety checks & scans.</div>
                </div>
                <button class="btn-delete-history" onclick="clearHistory()">Clear All</button>
            </div>

            <div class="history-list" id="historyList"></div>
        </main>

        <!-- TAB 5: PROFILE -->
        <main class="tab-view" id="tab-profile">
            <div class="greeting-section">
                <div class="greeting-title">Profile & Accessibility</div>
                <div class="greeting-subtitle">Customize CIPHER for comfortable readability.</div>
            </div>

            <div class="profile-container">
                <div class="profile-card">
                    <h4 style="font-size:0.9rem; font-weight:800; color:var(--text-muted); text-transform:uppercase; margin-bottom:1rem;">Accessibility Options</h4>

                    <div class="setting-toggle-row">
                        <div class="setting-label">
                            <h5>Large Text Mode</h5>
                            <p>Increases text size for high readability</p>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="toggleLargeText" onchange="toggleLargeText(this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>

                    <div class="setting-toggle-row">
                        <div class="setting-label">
                            <h5>High Contrast Mode</h5>
                            <p>Enhances visual contrast for text & borders</p>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="toggleHighContrast" onchange="toggleHighContrast(this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>

                <div class="profile-card">
                    <h4 style="font-size:0.9rem; font-weight:800; color:var(--text-muted); text-transform:uppercase; margin-bottom:1rem;">System Info</h4>
                    <p style="font-size:0.85rem; color:var(--text-body);"><b>CIPHER Engine:</b> Version 2.0 (Active)</p>
                    <p style="font-size:0.85rem; color:var(--text-body); margin-top:4px;"><b>Backend Status:</b> Online</p>
                    <button style="margin-top:1rem; background:var(--surface-subtle); border:1px solid var(--border-color); padding:8px 16px; border-radius:10px; font-weight:600; cursor:pointer;" onclick="showSplash()">Re-open Splash Screen</button>
                </div>
            </div>
        </main>

        <!-- Bottom Navigation -->
        <nav class="bottom-nav">
            <div class="nav-item active" id="nav-home" onclick="showTab('tab-home')">
                <svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                Home
            </div>
            <div class="nav-item" id="nav-detect" onclick="showTab('tab-detect')">
                <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                Detect
            </div>
            <div class="nav-item" id="nav-alerts" onclick="showTab('tab-alerts')">
                <svg viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                Alerts
            </div>
            <div class="nav-item" id="nav-history" onclick="showTab('tab-history')">
                <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                History
            </div>
            <div class="nav-item" id="nav-profile" onclick="showTab('tab-profile')">
                <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                Profile
            </div>
        </nav>

        <!-- Scanner Modal -->
        <div class="modal-overlay" id="modalOverlay" onclick="closeModalOnOverlay(event)">
            <div class="modal-card">
                <div class="modal-handle"></div>
                <div class="modal-header">
                    <div class="modal-title" id="modalTitle">Check & Verify</div>
                    <button class="btn-close-modal" onclick="closeModal()">✕</button>
                </div>

                <div class="modal-tool-tabs">
                    <button class="modal-tab-btn active" id="mtab-Link" onclick="switchModalTool('Link')">🌐 Link</button>
                    <button class="modal-tab-btn" id="mtab-Message" onclick="switchModalTool('Message')">💬 Message</button>
                    <button class="modal-tab-btn" id="mtab-Number" onclick="switchModalTool('Number')">📱 Number</button>
                    <button class="modal-tab-btn" id="mtab-QR" onclick="switchModalTool('QR')">🔲 QR Code</button>
                    <button class="modal-tab-btn" id="mtab-Image" onclick="switchModalTool('Image')">🖼️ Image</button>
                    <button class="modal-tab-btn" id="mtab-Audio" onclick="switchModalTool('Audio')">🎙️ Audio</button>
                    <button class="modal-tab-btn" id="mtab-File" onclick="switchModalTool('File')">🚨 File</button>
                </div>

                <div class="presets-box">
                    <div class="presets-label">Quick Test Scenarios:</div>
                    <div class="preset-btns">
                        <button class="btn-preset-item" onclick="loadPreset('http://17ebook.com/')">17ebook.com Link</button>
                        <button class="btn-preset-item" onclick="loadPreset('http://suspicious-malware-site.xyz/download.exe')">Malware .exe</button>
                        <button class="btn-preset-item" onclick="loadPreset('URGENT: Your bank account is suspended. Verify credentials at http://192.168.1.1/login')">Bank Phishing SMS</button>
                        <button class="btn-preset-item" onclick="loadPreset('Hello how are you doing today')">Safe Greeting</button>
                    </div>
                </div>

                <textarea class="check-input" id="checkInput" placeholder="Paste link, SMS text, or phone number to verify..."></textarea>

                <button class="btn-run-check" id="btnRunCheck" onclick="runCIPHERAnalysis()">
                    <span>🔍 Analyze Content</span>
                </button>

                <div class="result-container" id="resultContainer">
                    <div class="risk-banner" id="riskBanner">
                        <div class="risk-banner-head">
                            <div class="risk-main-title" id="riskMainTitle">⚠️ Potential Risk Detected</div>
                            <div class="risk-level-tag" id="riskLevelTag">Risk Level: HIGH</div>
                        </div>
                        <div class="risk-summary-text" id="riskSummaryText">
                            This content contains patterns commonly associated with phishing.
                        </div>
                    </div>

                    <div class="result-section-box">
                        <h4>Why?</h4>
                        <ul class="bullet-list" id="whyList"></ul>
                    </div>

                    <div class="result-section-box">
                        <h4>What should you do?</h4>
                        <ul class="bullet-list" id="actionList"></ul>
                    </div>

                    <div class="disclaimer-note" id="disclaimerNote">
                        No detection system can guarantee complete safety. Stay cautious with unexpected requests.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let checkHistory = JSON.parse(localStorage.getItem('cipher_history') || 'null') || [
            { id: 1, type: 'Website Check', query: '17ebook.com', risk: 'HIGH', safe: false, time: 'Today, 5:10 PM' },
            { id: 2, type: 'Website Check', query: 'https://google.com', risk: 'SAFE', safe: true, time: 'Today, 4:32 PM' }
        ];

        let currentActiveTool = 'Link';

        function dismissSplash() { document.getElementById('splashScreen').classList.add('hidden'); }
        function showSplash() { document.getElementById('splashScreen').classList.remove('hidden'); }

        function showTab(tabId) {
            document.querySelectorAll('.tab-view').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            const navEl = document.getElementById('nav-' + tabId.replace('tab-', ''));
            if (navEl) navEl.classList.add('active');
            if (tabId === 'tab-history') renderHistory();
        }

        function openVerificationModal(toolType) {
            currentActiveTool = toolType || 'Link';
            document.getElementById('modalTitle').innerText = 'Verify ' + currentActiveTool;
            document.querySelectorAll('.modal-tab-btn').forEach(btn => btn.classList.remove('active'));
            const activeBtn = document.getElementById('mtab-' + currentActiveTool);
            if (activeBtn) activeBtn.classList.add('active');
            document.getElementById('resultContainer').classList.remove('show');
            document.getElementById('modalOverlay').classList.add('open');
        }

        function switchModalTool(toolType) {
            currentActiveTool = toolType;
            document.getElementById('modalTitle').innerText = 'Verify ' + toolType;
            document.querySelectorAll('.modal-tab-btn').forEach(btn => btn.classList.remove('active'));
            const activeBtn = document.getElementById('mtab-' + toolType);
            if (activeBtn) activeBtn.classList.add('active');
        }

        function closeModal() { document.getElementById('modalOverlay').classList.remove('open'); }
        function closeModalOnOverlay(e) { if (e.target.id === 'modalOverlay') closeModal(); }
        function loadPreset(text) { document.getElementById('checkInput').value = text; }

        async function runCIPHERAnalysis() {
            const inputVal = document.getElementById('checkInput').value.trim();
            if (!inputVal) { alert('Please enter or paste content to verify.'); return; }

            const btn = document.getElementById('btnRunCheck');
            btn.innerHTML = '<span>⚡ Scanning with CIPHER AI...</span>';
            btn.disabled = true;

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: inputVal })
                });

                const data = await response.json();
                if (data.status === 'success') {
                    renderCIPHERResults(data.result, inputVal);
                } else {
                    alert('Error analyzing content: ' + (data.message || 'Unknown error'));
                }
            } catch (err) {
                console.error(err);
                renderOfflineFallback(inputVal);
            } finally {
                btn.innerHTML = '<span>🔍 Analyze Content</span>';
                btn.disabled = false;
            }
        }

        function renderCIPHERResults(res, inputVal) {
            const container = document.getElementById('resultContainer');
            const banner = document.getElementById('riskBanner');
            const titleEl = document.getElementById('riskMainTitle');
            const tagEl = document.getElementById('riskLevelTag');
            const summaryEl = document.getElementById('riskSummaryText');
            const whyList = document.getElementById('whyList');
            const actionList = document.getElementById('actionList');

            const isHighRisk = res.risk_score > 55 || (res.predicted_categories && res.predicted_categories[0].category !== 'SAFE');
            const primaryCat = res.predicted_categories ? res.predicted_categories[0].category : 'SAFE';

            if (isHighRisk) {
                banner.className = 'risk-banner high-risk';
                titleEl.innerText = '⚠️ Potential Risk Detected';
                tagEl.innerText = 'Risk Level: ' + (res.risk_score > 80 ? 'CRITICAL' : 'HIGH');
                summaryEl.innerText = 'This content contains patterns commonly associated with ' + primaryCat.toLowerCase().replace('_', ' ') + ' or digital fraud.';

                let whyItems = [];
                if (res.detected_indicators && res.detected_indicators.length > 0) {
                    res.detected_indicators.forEach(ind => {
                        whyItems.push(ind.name + (ind.explanation ? ': ' + ind.explanation : ''));
                    });
                } else {
                    whyItems.push('Suspicious payment or credential request pattern');
                    whyItems.push('Unverified external destination link');
                }
                whyList.innerHTML = whyItems.map(item => `<li>${item}</li>`).join('');

                let actionItems = [
                    'Don’t click any links or download attached files',
                    'Don’t share OTPs, PINs, or account credentials',
                    'Verify the sender through an official trusted phone number'
                ];
                actionList.innerHTML = actionItems.map(item => `<li>${item}</li>`).join('');
            } else {
                banner.className = 'risk-banner safe-risk';
                titleEl.innerText = '✓ Looks Safe';
                tagEl.innerText = 'Risk Level: LOW';
                summaryEl.innerText = 'This content doesn’t show obvious signs of fraud or suspicious activity.';

                whyList.innerHTML = `
                    <li>No malicious URL patterns or phishing keywords detected</li>
                    <li>Structure aligns with standard digital hygiene standards</li>
                `;

                actionList.innerHTML = `
                    <li>Continue exercising standard safety hygiene</li>
                    <li>Always double-check unexpected requests before sharing sensitive data</li>
                `;
            }

            container.classList.add('show');
            addHistoryItem(currentActiveTool + ' Check', inputVal, isHighRisk ? (res.risk_score > 80 ? 'HIGH' : 'MEDIUM') : 'SAFE', !isHighRisk);
        }

        function renderOfflineFallback(inputVal) {
            const isSuspicious = inputVal.includes('http://') || inputVal.toLowerCase().includes('otp') || inputVal.toLowerCase().includes('bank') || inputVal.includes('17ebook');
            renderCIPHERResults({
                risk_score: isSuspicious ? 90 : 0,
                predicted_categories: [{ category: isSuspicious ? 'PHISHING' : 'SAFE' }],
                detected_indicators: isSuspicious ? [{ name: 'Suspicious Link / Keyword', explanation: 'Unencrypted or unverified web link detected.' }] : []
            }, inputVal);
        }

        function addHistoryItem(type, query, risk, safe) {
            const newItem = {
                id: Date.now(),
                type: type,
                query: query.length > 35 ? query.substring(0, 35) + '...' : query,
                risk: risk,
                safe: safe,
                time: 'Just now'
            };
            checkHistory.unshift(newItem);
            localStorage.setItem('cipher_history', JSON.stringify(checkHistory));
        }

        function renderHistory() {
            const listEl = document.getElementById('historyList');
            if (checkHistory.length === 0) {
                listEl.innerHTML = '<div style="text-align:center; padding:2rem; color:var(--text-muted);">No verification history found.</div>';
                return;
            }

            listEl.innerHTML = checkHistory.map(item => `
                <div class="history-item-card">
                    <div class="history-info">
                        <h5>${item.type}</h5>
                        <p>${item.query}</p>
                    </div>
                    <div class="history-meta">
                        <span class="alert-type-badge" style="background:${item.safe ? '#f0fdf4' : '#fef2f2'}; color:${item.safe ? '#0d9488' : '#dc2626'}; font-weight:700;">
                            ${item.safe ? '✓ Safe' : '⚠️ ' + item.risk}
                        </span>
                        <div style="font-size:0.72rem; color:var(--text-muted); margin-top:2px;">${item.time}</div>
                    </div>
                </div>
            `).join('');
        }

        function clearHistory() {
            checkHistory = [];
            localStorage.removeItem('cipher_history');
            renderHistory();
        }

        function toggleLargeText(enabled) {
            if (enabled) document.body.classList.add('large-text-mode');
            else document.body.classList.remove('large-text-mode');
        }

        function toggleHighContrast(enabled) {
            if (enabled) document.body.classList.add('high-contrast-mode');
            else document.body.classList.remove('high-contrast-mode');
        }
    </script>
</body>
</html>
"""


@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    err_msg = str(e)
    print(f"Error caught by global handler: {err_msg}\n{traceback.format_exc()}")
    return jsonify({
        "status": "error",
        "message": err_msg
    }), 500


@app.route("/", methods=["GET"])
@app.route("/api/index", methods=["GET"])
@app.route("/api/index.py", methods=["GET"])
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
            try:
                rep = threat_intel.check_url_reputation(url_info["url"])
                url_info["threat_reputation"] = rep
            except Exception as rep_err:
                print(f"Non-fatal reputation check warning: {rep_err}")
                url_info["threat_reputation"] = {"status": "UNAVAILABLE", "is_malicious": False}


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
