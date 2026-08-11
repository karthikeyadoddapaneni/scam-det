"""
SafeGuard AI - Threat Intelligence & Reputation Interface
"""

import os
from typing import Dict, Any, Optional


class ThreatIntelProvider:
    """
    Extensible interface architecture for integrating external threat intelligence
    APIs (e.g. VirusTotal, AbuseIPDB, Google Safe Browsing, AlienVault OTX).
    """
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("SAFEGUARD_INTEL_API_KEY")
        
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Queries external IP reputation feed if key is present."""
        if not self.api_key:
            return {
                "query": ip_address,
                "status": "UNCONFIGURED",
                "message": "Reputation data unavailable — no external reputation source configured.",
                "reputation_score": None,
                "is_malicious": False
            }
        # Provider API integration placeholder
        return {
            "query": ip_address,
            "status": "CONFIGURED_STUB",
            "message": "External API key configured. Ready for live threat lookup.",
            "reputation_score": 0,
            "is_malicious": False
        }

    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Queries external domain reputation feed if key is present."""
        if not self.api_key:
            return {
                "query": domain,
                "status": "UNCONFIGURED",
                "message": "Reputation data unavailable — no external reputation source configured.",
                "reputation_score": None,
                "is_malicious": False
            }
        return {
            "query": domain,
            "status": "CONFIGURED_STUB",
            "message": "External API key configured. Ready for live threat lookup.",
            "reputation_score": 0,
            "is_malicious": False
        }

    def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Queries external URL reputation feed if key is present."""
        if not self.api_key:
            return {
                "query": url,
                "status": "UNCONFIGURED",
                "message": "Reputation data unavailable — no external reputation source configured.",
                "reputation_score": None,
                "is_malicious": False
            }
        return {
            "query": url,
            "status": "CONFIGURED_STUB",
            "message": "External API key configured. Ready for live threat lookup.",
            "reputation_score": 0,
            "is_malicious": False
        }

