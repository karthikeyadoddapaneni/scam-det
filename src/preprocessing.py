"""
SafeGuard AI - Text Preprocessing and Normalization Module
"""

import re
import string
import nltk

# Use robust offline fallback stopwords and lemmatization
STOP_WORDS = {
    'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', "you're", "you've",
    "you'll", "you'd", 'your', 'yours', 'yourself', 'yourselves', 'he', 'him', 'his',
    'himself', 'she', "she's", 'her', 'hers', 'herself', 'it', "it's", 'its', 'itself',
    'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which', 'who', 'whom',
    'this', 'that', "that'll", 'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be',
    'been', 'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'a',
    'an', 'the', 'and', 'but', 'if', 'or', 'because', 'as', 'until', 'while', 'of', 'at',
    'by', 'for', 'with', 'about', 'against', 'between', 'into', 'through', 'during',
    'before', 'after', 'above', 'below', 'to', 'from', 'up', 'down', 'in', 'out', 'on',
    'off', 'over', 'under', 'again', 'further', 'then', 'once'
}
LEMMATIZER = None
try:
    from nltk.corpus import stopwords
    from nltk.stem import WordNetLemmatizer
    STOP_WORDS.update(set(stopwords.words('english')))
    LEMMATIZER = WordNetLemmatizer()
except Exception:
    pass


def clean_text(text: str) -> str:
    """
    Normalizes text while preserving contextually important cybersecurity tokens
    such as currency symbols, urgency cues, and URL tokens.
    """
    if not isinstance(text, str):
        return ""
    
    # 1. Standardize lowercasing
    text = text.lower()
    
    # 2. Tokenize URL placeholders while retaining URL presence info
    text = re.sub(r'https?://\S+|www\.\S+', ' url_token ', text)
    
    # 3. Tokenize emails, phone numbers, and IP addresses
    text = re.sub(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', ' email_token ', text)
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ' ip_token ', text)
    text = re.sub(r'\b\d{10}\b|\b\d{3}[-\s]\d{3}[-\s]\d{4}\b', ' phone_token ', text)
    
    # 4. Standardize currency and financial amount indicators
    text = re.sub(r'[$\u20b9\u20ac\u00a3]\s?\d+(?:,\d+)*(?:\.\d+)?', ' currency_token ', text)
    text = re.sub(r'\b\d+\s?(?:usd|inr|btc|bitcoin|dollars|rupees|eth)\b', ' currency_token ', text)
    
    # 5. Remove excessive punctuation while preserving word boundaries
    text = re.sub(r'[^a-z0-9_\s$%\u20b9]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def preprocess_tokens(text: str, remove_stopwords: bool = True) -> str:
    """
    Full preprocessing pipeline: cleaning, tokenizing, optional stopword removal,
    and lemmatization.
    """
    cleaned = clean_text(text)
    tokens = cleaned.split()
    
    processed = []
    for token in tokens:
        if remove_stopwords and token in STOP_WORDS and token not in {'or', 'if', 'not', 'no', 'you', 'your', 'me', 'my', 'pay', 'send'}:
            continue
        if LEMMATIZER:
            try:
                token = LEMMATIZER.lemmatize(token)
            except Exception:
                pass
        processed.append(token)
        
    return " ".join(processed)


if __name__ == "__main__":
    sample = "URGENT: Pay me ₹50,000 via http://scam.site/login or your account will be blocked!"
    print("Original:", sample)
    print("Cleaned: ", clean_text(sample))
    print("Tokens:  ", preprocess_tokens(sample))
