"""
SafeGuard AI - URL Analysis Module
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any

URL_REGEX = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".ml", ".info", ".site", ".online", ".ru", ".cc", ".work", ".click", ".tk"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "update", "bank", "account", "netbanking", "billing", "confirm", "signin", "support", "auth", "password", "credential"}
MALWARE_EXTENSIONS = {".exe", ".apk", ".scr", ".bat", ".vbs", ".zip", ".msi", ".jar", ".ps1", ".cmd", ".dll", ".rar", ".iso", ".img", ".7z", ".sh", ".dmg", ".bin", ".elf"}


def analyze_urls_in_text(text: str) -> List[Dict[str, Any]]:
    """
    Extracts and evaluates static indicators of URLs embedded in input text.
    Operates 100% offline without visiting or pinging target links.
    """
    raw_urls = re.findall(URL_REGEX, text)
    results = []
    
    for url in raw_urls:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_path_query = (parsed.path + "?" + parsed.query).lower()
        
        indicators = []
        risk_weight = 0.0
        threat_tags = []
        
        # 1. Malware Executable Payload Check
        has_malware_ext = any(full_path_query.endswith(ext) or f"{ext}?" in full_path_query or f"{ext}&" in full_path_query for ext in MALWARE_EXTENSIONS)
        if has_malware_ext:
            indicators.append("High-risk malware/executable payload extension detected (.exe, .apk, .zip, etc.)")
            risk_weight += 4.0
            threat_tags.append("MALWARE_PAYLOAD")

        # 2. IP-based Domain Check
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain))
        if is_ip:
            indicators.append("IP-address-based URL host detected instead of standard domain name")
            risk_weight += 3.0
            threat_tags.append("IP_HOST")
            
        # 3. Suspicious Path Keywords
        found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in domain]
        if found_kw:
            indicators.append(f"Contains credential/banking keywords: {', '.join(found_kw)}")
            risk_weight += 2.5
            threat_tags.append("CREDENTIAL_PHISHING")

        # 4. Suspicious TLD Check
        has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            indicators.append("Uses non-standard/high-risk Top Level Domain (TLD)")
            risk_weight += 2.0
            threat_tags.append("HIGH_RISK_TLD")

        # 5. URL Shortener Check
        is_shortened = any(s in domain for s in SHORTENERS)
        if is_shortened:
            indicators.append("URL shortening service used (masks real target destination)")
            risk_weight += 1.5
            threat_tags.append("URL_SHORTENER")

        # 6. Scheme Check
        is_https = parsed.scheme.lower() == "https"
        if not is_https:
            indicators.append("Uses unencrypted HTTP protocol instead of HTTPS")
            risk_weight += 1.0
            
        # 7. Subdomain Count Check
        subdomain_parts = domain.split(".")
        if len(subdomain_parts) > 3 and not is_ip:
            indicators.append(f"High number of subdomains detected ({len(subdomain_parts)} parts)")
            risk_weight += 1.0
            
        # 8. Length Check
        if len(url) > 75:
            indicators.append(f"Excessive URL length ({len(url)} characters)")
            risk_weight += 0.5

        suspicious = len(indicators) > 0 and risk_weight >= 1.5

        results.append({
            "url": url,
            "domain": domain,
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
    test_text = "Verify your account at http://192.168.1.1/login-verify or download malware from http://suspicious.xyz/file.exe"
    urls_res = analyze_urls_in_text(test_text)
    for u in urls_res:
        print("URL:", u["url"])
        print("Weight:", u["risk_weight"])
        print("Indicators:", u["indicators"])

