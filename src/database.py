"""
SafeGuard AI - Database & User Feedback Storage Engine
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Any

DB_PATH = "safeguard_ai.db"


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Returns a SQLite connection with dict row factory."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DB_PATH):
    """Creates SQLite tables for message analysis history and user feedback."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # 1. Analysis History Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                text_snippet TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                categories TEXT NOT NULL,
                indicator_count INTEGER NOT NULL
            );
        """)
        
        # 2. User Feedback Reporting Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                analysis_id INTEGER,
                predicted_category TEXT NOT NULL,
                feedback_status TEXT NOT NULL,
                user_comment TEXT,
                FOREIGN KEY (analysis_id) REFERENCES analysis_history (id)
            );
        """)
        conn.commit()


def log_analysis(prediction_result: Dict[str, Any], text: str, db_path: str = DB_PATH) -> int:
    """Logs an anonymous analysis transaction into the database."""
    init_db(db_path)
    timestamp = datetime.now().isoformat()
    snippet = text[:150] + "..." if len(text) > 150 else text
    categories_json = json.dumps([c["category"] for c in prediction_result.get("predicted_categories", [])])
    indicator_count = len(prediction_result.get("detected_indicators", []))
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analysis_history (timestamp, text_snippet, risk_score, risk_level, categories, indicator_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, snippet, prediction_result["risk_score"], prediction_result["risk_level"], categories_json, indicator_count))
        conn.commit()
        return cursor.lastrowid


def log_user_feedback(analysis_id: int, predicted_cat: str, status: str, comment: str = "", db_path: str = DB_PATH):
    """Saves user feedback report (Correct / Incorrect / Unsure)."""
    init_db(db_path)
    timestamp = datetime.now().isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_feedback (timestamp, analysis_id, predicted_category, feedback_status, user_comment)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, analysis_id, predicted_cat, status, comment))
        conn.commit()


def get_summary_analytics(db_path: str = DB_PATH) -> Dict[str, Any]:
    """Retrieves system analytics summary from local SQLite database."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Total Analyzed
        cursor.execute("SELECT COUNT(*) as total FROM analysis_history")
        total_analyzed = cursor.fetchone()["total"]
        
        # High/Critical Risk count
        cursor.execute("SELECT COUNT(*) as high_risk FROM analysis_history WHERE risk_score >= 56")
        high_risk_count = cursor.fetchone()["high_risk"]
        
        # Feedback count
        cursor.execute("SELECT feedback_status, COUNT(*) as count FROM user_feedback GROUP BY feedback_status")
        feedback_rows = cursor.fetchall()
        feedback_counts = {r["feedback_status"]: r["count"] for r in feedback_rows}
        
        # Category breakdown
        cursor.execute("SELECT categories FROM analysis_history")
        all_cats_rows = cursor.fetchall()
        
        cat_counts = {}
        for r in all_cats_rows:
            try:
                cats = json.loads(r["categories"])
                for c in cats:
                    cat_counts[c] = cat_counts.get(c, 0) + 1
            except Exception:
                pass

        return {
            "total_analyzed": total_analyzed,
            "high_risk_count": high_risk_count,
            "feedback_counts": feedback_counts,
            "category_distribution": cat_counts
        }


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
