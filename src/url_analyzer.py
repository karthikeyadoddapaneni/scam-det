"""
SafeGuard AI - URL Analysis Module
"""

import re
import socket
from urllib.parse import urlparse
from typing import List, Dict, Any

URL_REGEX = r"(?:https?://|www\.)[^\s<>\"']+|\b[a-zA-Z0-9-]+\.(?:com|org|net|info|xyz|top|site|online|ru|cc|work|click|tk|apk|exe|app|in|io|co|me|store|live|cfd|sbs|monster|bid|win|quest|icu|buzz)\b(?:/[^\s<>\"']*)?"

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".ml", ".info", ".site", ".online", ".ru", ".cc", ".work", ".click", ".tk", ".biz", ".download", ".link", ".live", ".store", ".asia", ".club", ".space", ".monster", ".fit", ".rest", ".shop", ".beauty", ".hair", ".quest", ".icu", ".buzz", ".win", ".bid", ".life", ".cfd", ".sbs", ".best", ".cam", ".cyou", ".fun", ".uno", ".vip", ".wang"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "update", "bank", "account", "netbanking", "billing", "confirm", "signin", "support", "auth", "password", "credential", "reset", "kyc"}
SKETCHY_DOMAIN_KEYWORDS = {
    "ebook", "warez", "crack", "keygen", "modapk", "torrent", "freepdf", "freebook", "123movies", 
    "streaming", "cheat", "hack", "nulled", "unlocked", "roms", "emulator", "paytm", "gpay", 
    "phonepe", "cashback", "bonus", "airdrop", "crypto", "recharge", "spinwin", "scratchcard", 
    "giftcard", "freestuff", "unclaimed", "libgen", "pdfdrive", "oceanofpdf", "apkmody", "an1", 
    "happymod", "rexdl", "revdl", "fitgirl", "getintopc", "sbi-kyc", "hdfc-netbank", "icici-reward", 
    "paypal-verify", "netflix-billing", "apple-id-verify", "kbc-lottery", "double-btc"
}
MALWARE_EXTENSIONS = {".exe", ".apk", ".scr", ".bat", ".vbs", ".zip", ".msi", ".jar", ".ps1", ".cmd", ".dll", ".rar", ".iso", ".img", ".7z", ".sh", ".dmg", ".bin", ".elf"}

# Global Top Trusted Domains Whitelist
TRUSTED_GLOBAL_DOMAINS = {
    "google.com", "www.google.com", "youtube.com", "www.youtube.com", "facebook.com", "instagram.com",
    "wikipedia.org", "en.wikipedia.org", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "linkedin.com", "twitter.com", "x.com", "netflix.com", "reddit.com", "yahoo.com", "bing.com",
    "duckduckgo.com", "cloudflare.com", "gov.in", "india.gov.in", "usa.gov", "bbc.com", "cnn.com",
    "nytimes.com", "chatgpt.com", "openai.com", "stackoverflow.com", "medium.com", "adobe.com",
    "zoom.us", "dropbox.com", "quora.com", "spotify.com", "whatsapp.com", "telegram.org"
}

# Known parked or adware/malware hosting IP networks
SUSPICIOUS_IP_PREFIXES = ("208.91.112.", "192.168.", "10.", "127.0.0.1", "0.0.0.0")


def analyze_urls_in_text(text: str) -> List[Dict[str, Any]]:
    """
    Extracts and evaluates static and DNS indicators of URLs embedded in input text.
    Includes global domain whitelist checking to prevent false positives on legitimate services.
    """
    raw_urls = re.findall(URL_REGEX, text)
    results = []
    seen_urls = set()
    
    for url in raw_urls:
        if url in seen_urls:
            continue
        seen_urls.add(url)

        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
        path = parsed.path.lower()
        full_path_query = (parsed.path + "?" + parsed.query).lower()
        
        # Clean port if present in domain string
        clean_domain = domain.split(":")[0]
        
        # Extract registered main domain (e.g. google.com from sub.google.com)
        domain_parts = clean_domain.split(".")
        main_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else clean_domain

        indicators = []
        risk_weight = 0.0
        threat_tags = []

        # 1. Malware Executable Payload Check
        has_malware_ext = any(full_path_query.endswith(ext) or f"{ext}?" in full_path_query or f"{ext}&" in full_path_query for ext in MALWARE_EXTENSIONS)
        if has_malware_ext:
            indicators.append("High-risk malware/executable payload extension detected (.exe, .apk, .zip, etc.)")
            risk_weight += 4.0
            threat_tags.append("MALWARE_PAYLOAD")

        # 2. Check Whitelist for Recognized Trusted Global Domain
        if (clean_domain in TRUSTED_GLOBAL_DOMAINS or main_domain in TRUSTED_GLOBAL_DOMAINS) and not has_malware_ext:
            results.append({
                "url": url,
                "domain": clean_domain,
                "resolved_ip": None,
                "is_https": parsed.scheme.lower() == "https",
                "is_ip": False,
                "is_shortened": False,
                "has_malware_ext": False,
                "indicators": [],
                "suspicious_count": 0,
                "risk_weight": 0.0,
                "threat_tags": ["TRUSTED_WHITELIST"],
                "suspicious": False,
                "assessment": "Verified legitimate domain"
            })
            continue

        # 3. IP-based Domain Check
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_domain))
        if is_ip:
            indicators.append("IP-address-based URL host detected instead of standard domain name")
            risk_weight += 3.5
            threat_tags.append("IP_HOST")

        # 4. Sketchy Domain Keyword Check (e.g. 17ebook, freepdf, modapk, torrent, paytm-bonus)
        found_domain_kw = [kw for kw in SKETCHY_DOMAIN_KEYWORDS if kw in clean_domain]
        if found_domain_kw:
            indicators.append(f"Domain name contains high-risk piracy/untrusted keywords: {', '.join(found_domain_kw)}")
            risk_weight += 3.0
            threat_tags.append("SKETCHY_DOMAIN_KEYWORD")

        # 5. Digit-Prefixed/Suffixed Domain Structure (e.g., 17ebook, 99bet, 123movies)
        if re.search(r"^\d+[a-z]{3,}", clean_domain) or re.search(r"[a-z]{3,}\d+\.[a-z]+$", clean_domain):
            indicators.append("Digit-prefixed/suffixed domain structure commonly used in spam & piracy mirrors")
            risk_weight += 2.5
            threat_tags.append("NUMERIC_DOMAIN_SPOOF")

        # 6. Suspicious Path & Credential Keywords
        found_path_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in clean_domain]
        if found_path_kw:
            indicators.append(f"Contains credential/banking keywords: {', '.join(found_path_kw)}")
            risk_weight += 2.5
            threat_tags.append("CREDENTIAL_PHISHING")

        # 7. Suspicious TLD Check
        has_suspicious_tld = any(clean_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            indicators.append("Uses non-standard/high-risk Top Level Domain (TLD)")
            risk_weight += 2.2
            threat_tags.append("HIGH_RISK_TLD")

        # 8. URL Shortener Check
        is_shortened = any(s in clean_domain for s in SHORTENERS)
        if is_shortened:
            indicators.append("URL shortening service used (masks real target destination)")
            risk_weight += 1.8
            threat_tags.append("URL_SHORTENER")

        # 9. Scheme Check
        is_https = parsed.scheme.lower() == "https"
        if not is_https:
            indicators.append("Uses unencrypted HTTP protocol instead of HTTPS")
            risk_weight += 1.5
            
        # 10. Live DNS Host & Parking IP Check
        resolved_ip = None
        if not is_ip:
            try:
                socket.setdefaulttimeout(1.2)
                resolved_ip = socket.gethostbyname(clean_domain)
                if resolved_ip and any(resolved_ip.startswith(prefix) for prefix in SUSPICIOUS_IP_PREFIXES):
                    indicators.append(f"Domain resolves to known parked/adware IP block ({resolved_ip})")
                    risk_weight += 3.0
                    threat_tags.append("PARKED_SUSPICIOUS_IP")
            except Exception:
                pass # Non-fatal DNS lookup failure

        # 11. Subdomain Count Check
        if len(domain_parts) > 3 and not is_ip:
            indicators.append(f"High number of subdomains detected ({len(domain_parts)} parts)")
            risk_weight += 1.0
            
        # 12. Length Check
        if len(url) > 75:
            indicators.append(f"Excessive URL length ({len(url)} characters)")
            risk_weight += 0.5

        suspicious = len(indicators) > 0 and risk_weight >= 1.5

        results.append({
            "url": url,
            "domain": clean_domain,
            "resolved_ip": resolved_ip,
            "is_https": is_https,
            "is_ip": is_ip,
            "is_shortened": is_shortened,
            "has_malware_ext": has_malware_ext,
            "indicators": indicators,
            "suspicious_count": len(indicators),
            "risk_weight": round(risk_weight, 2),
            "threat_tags": threat_tags,
            "suspicious": suspicious,
            "assessment": "High-risk suspicious URL anomalies detected" if suspicious else ("Minor URL warning" if indicators else "Standard domain name")
        })
        
    return results


if __name__ == "__main__":
    test_text = "Check http://17ebook.com/ or http://192.168.1.1/login or http://suspicious.xyz/file.exe"
    urls_res = analyze_urls_in_text(test_text)
    for u in urls_res:
        print("URL:", u["url"])
        print("Weight:", u["risk_weight"])
        print("Indicators:", u["indicators"])


