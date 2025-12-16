"""
Enhanced Dataset Preparation with 6 Advanced Features
This adds URL entropy, digit ratio, and other powerful features
"""

import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
import math
import tldextract

def calculate_url_entropy(url):
    """Calculate Shannon entropy - measures randomness"""
    if not url or len(url) == 0:
        return 0
    prob = [url.count(c)/len(url) for c in set(url)]
    entropy = -sum(p * math.log2(p) for p in prob if p > 0)
    return entropy

def get_digit_ratio(url):
    """Ratio of digits to total characters"""
    if len(url) == 0:
        return 0
    digits = sum(c.isdigit() for c in url)
    return digits / len(url)

def get_special_char_count(url):
    """Count of special characters"""
    special = sum(not c.isalnum() and c not in [':', '/', '.', '-', '_'] for c in url)
    return special

def check_suspicious_tld(url):
    """Check for suspicious top-level domains"""
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'cc', 'pw', 'top', 'xyz', 'info', 'click']
    try:
        ext = tldextract.extract(url)
        return 1 if ext.suffix in suspicious_tlds else -1
    except:
        return 0

def count_subdomain_levels(url):
    """Count subdomain depth"""
    try:
        ext = tldextract.extract(url)
        if not ext.subdomain:
            return 0
        return len(ext.subdomain.split('.'))
    except:
        return 0

def get_path_length(url):
    """Length of URL path"""
    try:
        parsed = urlparse(url)
        return len(parsed.path)
    except:
        return 0

def extract_features_from_url_enhanced(url):
    """
    Extract 22 features (16 original + 6 advanced) from a URL
    """
    
    # Clean URL
    url = url.strip()
    if not url.startswith('http'):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        full_url = url
    except:
        return [0] * 22
    
    features = []
    
    # Original 16 features
    # 1. isIPInURL
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else -1)
    
    # 2. isLongURL
    if len(url) < 54:
        features.append(-1)
    elif len(url) <= 75:
        features.append(0)
    else:
        features.append(1)
    
    # 3. isTinyURL
    features.append(1 if len(url) <= 20 else -1)
    
    # 4. isAlphaNumericURL
    features.append(1 if '@' in url else -1)
    
    # 5. isRedirectingURL
    if url.startswith('http://'):
        redirect_check = url[7:].count('//')
    elif url.startswith('https://'):
        redirect_check = url[8:].count('//')
    else:
        redirect_check = 0
    features.append(1 if redirect_check > 0 else -1)
    
    # 6. isHypenURL
    domain_only = domain.split('/')[0]
    features.append(1 if '-' in domain_only else -1)
    
    # 7. isMultiDomainURL
    subdomain_count = domain.count('.')
    features.append(1 if subdomain_count >= 4 else -1)
    
    # 8. isFaviconDomainUnidentical
    suspicious_patterns = ['paypal', 'ebay', 'login', 'secure', 'account', 'verify', 
                          'update', 'confirm', 'banking', 'signin']
    has_suspicious = any(pattern in url.lower() for pattern in suspicious_patterns)
    features.append(1 if has_suspicious and len(domain.split('.')) > 3 else -1)
    
    # 9. isIllegalHttpsURL
    features.append(1 if 'https' in url[8:] else -1)
    
    # 10-16. Other original features
    features.append(1 if subdomain_count >= 3 else -1)  # isImgFromDifferentDomain
    features.append(1 if len(path) > 50 or subdomain_count >= 3 else -1)  # isAnchorFromDifferentDomain
    features.append(1 if subdomain_count >= 3 else -1)  # isScLnkFromDifferentDomain
    form_suspicious = any(word in url.lower() for word in ['cgi-bin', 'webscr', 'cmd', 'login'])
    features.append(1 if form_suspicious else -1)  # isFormActionInvalid
    features.append(1 if 'mailto' in url.lower() else -1)  # isMailToAvailable
    features.append(1 if len(path) > 100 or url.count('?') > 1 else -1)  # isStatusBarTampered
    features.append(1 if 'iframe' in url.lower() or 'frame' in url.lower() else -1)  # isIframePresent
    
    # NEW: 6 Advanced Features
    # 17. URL Entropy (high = random/suspicious)
    entropy = calculate_url_entropy(url)
    features.append(1 if entropy > 4.5 else (-1 if entropy < 3.5 else 0))
    
    # 18. Digit Ratio (high = suspicious)
    digit_ratio = get_digit_ratio(url)
    features.append(1 if digit_ratio > 0.3 else (-1 if digit_ratio < 0.1 else 0))
    
    # 19. Special Character Count (high = suspicious)
    special_count = get_special_char_count(url)
    features.append(1 if special_count > 15 else (-1 if special_count < 5 else 0))
    
    # 20. Suspicious TLD
    features.append(check_suspicious_tld(url))
    
    # 21. Subdomain Depth (high = suspicious)
    subdomain_depth = count_subdomain_levels(url)
    features.append(1 if subdomain_depth > 2 else (-1 if subdomain_depth == 0 else 0))
    
    # 22. Path Length (very long = suspicious)
    path_len = get_path_length(url)
    features.append(1 if path_len > 100 else (-1 if path_len < 20 else 0))
    
    return features

def load_urls_from_file(filepath):
    """Load URLs from text file"""
    urls = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    urls.append(url)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
    return urls

def prepare_enhanced_dataset(malicious_file, suspicious_file):
    """
    Prepare dataset with 22 features (16 original + 6 advanced)
    """
    print("="*60)
    print("ENHANCED DATASET PREPARATION (22 FEATURES)")
    print("="*60)
    
    # Load URLs
    print("\n[1/4] Loading URLs...")
    malicious_urls = load_urls_from_file(malicious_file)
    suspicious_urls = load_urls_from_file(suspicious_file)
    
    print(f"  ✓ Loaded {len(malicious_urls)} malicious URLs")
    print(f"  ✓ Loaded {len(suspicious_urls)} suspicious URLs")
    
    # Generate safe URLs
    print("\n[2/4] Generating safe URLs...")
    safe_urls = [
        'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'reddit.com', 'netflix.com',
        'github.com', 'stackoverflow.com', 'microsoft.com', 'apple.com', 'yahoo.com',
        'bbc.com', 'cnn.com', 'nytimes.com', 'washingtonpost.com', 'theguardian.com',
    ] * 200  # Repeat to create more samples
    
    # Balance dataset
    num_samples = min(len(malicious_urls), len(suspicious_urls), len(safe_urls))
    num_samples = min(num_samples, 4000)
    
    print(f"  ✓ Using {num_samples} samples per class")
    
    malicious_sample = malicious_urls[:num_samples]
    suspicious_sample = suspicious_urls[:num_samples]
    safe_sample = safe_urls[:num_samples]
    
    # Extract features
    print("\n[3/4] Extracting 22 features from URLs...")
    print("  - 16 original features")
    print("  - 6 advanced features (entropy, digit ratio, TLD, etc.)")
    
    X_malicious = []
    for i, url in enumerate(malicious_sample):
        features = extract_features_from_url_enhanced(url)
        X_malicious.append(features)
        if (i + 1) % 500 == 0:
            print(f"  - Processed {i + 1}/{len(malicious_sample)} malicious URLs")
    
    X_suspicious = []
    for i, url in enumerate(suspicious_sample):
        features = extract_features_from_url_enhanced(url)
        X_suspicious.append(features)
        if (i + 1) % 500 == 0:
            print(f"  - Processed {i + 1}/{len(suspicious_sample)} suspicious URLs")
    
    X_safe = []
    for i, url in enumerate(safe_sample):
        features = extract_features_from_url_enhanced(url)
        X_safe.append(features)
        if (i + 1) % 500 == 0:
            print(f"  - Processed {i + 1}/{len(safe_sample)} safe URLs")
    
    # Combine
    print("\n[4/4] Combining dataset...")
    X = np.array(X_malicious + X_suspicious + X_safe)
    y = np.array([1] * len(X_malicious) + [0] * len(X_suspicious) + [-1] * len(X_safe))
    
    # Save
    feature_names = [
        'isIPInURL', 'isLongURL', 'isTinyURL', 'isAlphaNumericURL', 
        'isRedirectingURL', 'isHypenURL', 'isMultiDomainURL', 
        'isFaviconDomainUnidentical', 'isIllegalHttpsURL', 
        'isImgFromDifferentDomain', 'isAnchorFromDifferentDomain', 
        'isScLnkFromDifferentDomain', 'isFormActionInvalid', 
        'isMailToAvailable', 'isStatusBarTampered', 'isIframePresent',
        'urlEntropy', 'digitRatio', 'specialCharCount', 
        'suspiciousTLD', 'subdomainDepth', 'pathLength'
    ]
    
    df = pd.DataFrame(X, columns=feature_names)
    df['label'] = y
    df.to_csv('website_dataset_enhanced.csv', index=False)
    
    print(f"\n✓ Enhanced dataset saved: website_dataset_enhanced.csv")
    print(f"  Total samples: {len(X)}")
    print(f"  Features: 22 (16 original + 6 advanced)")
    
    return X, y

if __name__ == "__main__":
    # Install required library if needed
    try:
        import tldextract
    except:
        print("Installing tldextract...")
        import subprocess
        subprocess.check_call(['pip', 'install', 'tldextract'])
        import tldextract
    
    prepare_enhanced_dataset('virustotalresult_malicious.txt', 'virustotalresult_suspicious.txt')
    
    print("\n✅ Next step: python train_model.py")
    print("   (Update train_model.py to use 'website_dataset_enhanced.csv')")
