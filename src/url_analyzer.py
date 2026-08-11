"""
SafeGuard AI - URL Analysis Module
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any

URL_REGEX = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".ml", ".info", ".site", ".online", ".ru", ".cc", ".work", ".click", ".tk"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "update", "bank", "account", "netbanking", "billing", "confirm", "signin", "support"}


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
        
        indicators = []
        
        # 1. Scheme Check
        is_https = parsed.scheme.lower() == "https"
        if not is_https:
            indicators.append("Uses unencrypted HTTP protocol instead of HTTPS")
            
        # 2. IP-based Domain Check
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain))
        if is_ip:
            indicators.append("IP-address-based URL host detected instead of standard domain name")
            
        # 3. URL Shortener Check
        is_shortened = any(s in domain for s in SHORTENERS)
        if is_shortened:
            indicators.append("URL shortening service used (masks real target destination)")
            
        # 4. Length Check
        if len(url) > 75:
            indicators.append(f"Excessive URL length ({len(url)} characters)")
            
        # 5. Subdomain Count Check
        subdomain_parts = domain.split(".")
        if len(subdomain_parts) > 3 and not is_ip:
            indicators.append(f"High number of subdomains detected ({len(subdomain_parts)} parts)")
            
        # 6. Suspicious TLD Check
        has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            indicators.append("Uses non-standard/high-risk Top Level Domain (TLD)")
            
        # 7. Suspicious Path Keywords
        found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in domain]
        if found_kw:
            indicators.append(f"Contains credential/banking keywords: {', '.join(found_kw)}")
            
        results.append({
            "url": url,
            "domain": domain,
            "is_https": is_https,
            "is_ip": is_ip,
            "is_shortened": is_shortened,
            "indicators": indicators,
            "suspicious_count": len(indicators),
            "assessment": "Potentially suspicious URL indicators found" if indicators else "No obvious static URL anomalies detected"
        })
        
    return results


if __name__ == "__main__":
    test_text = "Verify your account at http://192.168.1.1/login-verify or visit http://bit.ly/bank-update"
    urls_res = analyze_urls_in_text(test_text)
    for u in urls_res:
        print("URL:", u["url"])
        print("Indicators:", u["indicators"])
