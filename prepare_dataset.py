"""
Dataset Preparation Script for VirusTotal Data
This script prepares the training dataset from real malicious and suspicious URLs
"""

import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re

def extract_features_from_url(url):
    """
    Extract 16 features from a URL without loading the actual website
    Features: [isIPInURL, isLongURL, isTinyURL, isAlphaNumericURL, isRedirectingURL,
               isHypenURL, isMultiDomainURL, isFaviconDomainUnidentical, isIllegalHttpsURL,
               isImgFromDifferentDomain, isAnchorFromDifferentDomain, isScLnkFromDifferentDomain,
               isFormActionInvalid, isMailToAvailable, isStatusBarTampered, isIframePresent]
    
    Note: Some features require page content, so we'll use heuristics based on URL patterns
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
        # If parsing fails, return neutral values
        return [0] * 16
    
    features = []
    
    # 1. isIPInURL - Check if URL contains IP address
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else -1)
    
    # 2. isLongURL - Check URL length
    if len(url) < 54:
        features.append(-1)
    elif len(url) <= 75:
        features.append(0)
    else:
        features.append(1)
    
    # 3. isTinyURL - Very short URLs
    features.append(1 if len(url) <= 20 else -1)
    
    # 4. isAlphaNumericURL - Contains @ symbol
    features.append(1 if '@' in url else -1)
    
    # 5. isRedirectingURL - Multiple // in URL
    if url.startswith('http://'):
        redirect_check = url[7:].count('//')
    elif url.startswith('https://'):
        redirect_check = url[8:].count('//')
    else:
        redirect_check = 0
    features.append(1 if redirect_check > 0 else -1)
    
    # 6. isHypenURL - Hyphen in domain
    domain_only = domain.split('/')[0]
    features.append(1 if '-' in domain_only else -1)
    
    # 7. isMultiDomainURL - Number of subdomains
    subdomain_count = domain.count('.')
    features.append(1 if subdomain_count >= 4 else -1)
    
    # 8. isFaviconDomainUnidentical - Heuristic: suspicious patterns
    suspicious_patterns = ['paypal', 'ebay', 'login', 'secure', 'account', 'verify', 
                          'update', 'confirm', 'banking', 'signin']
    has_suspicious = any(pattern in url.lower() for pattern in suspicious_patterns)
    features.append(1 if has_suspicious and len(domain.split('.')) > 3 else -1)
    
    # 9. isIllegalHttpsURL - HTTPS in URL path (not protocol)
    features.append(1 if 'https' in url[8:] else -1)
    
    # 10. isImgFromDifferentDomain - Heuristic: multiple domains in URL
    features.append(1 if subdomain_count >= 3 else -1)
    
    # 11. isAnchorFromDifferentDomain - Heuristic based on complex URLs
    features.append(1 if len(path) > 50 or subdomain_count >= 3 else -1)
    
    # 12. isScLnkFromDifferentDomain - Similar heuristic
    features.append(1 if subdomain_count >= 3 else -1)
    
    # 13. isFormActionInvalid - Check for suspicious form patterns
    form_suspicious = any(word in url.lower() for word in ['cgi-bin', 'webscr', 'cmd', 'login'])
    features.append(1 if form_suspicious else -1)
    
    # 14. isMailToAvailable - Check for mailto in URL
    features.append(1 if 'mailto' in url.lower() else -1)
    
    # 15. isStatusBarTampered - Heuristic: very long paths or many parameters
    features.append(1 if len(path) > 100 or url.count('?') > 1 else -1)
    
    # 16. isIframePresent - Heuristic: iframe keyword in URL
    features.append(1 if 'iframe' in url.lower() or 'frame' in url.lower() else -1)
    
    return features

def load_urls_from_file(filepath):
    """Load URLs from text file"""
    urls = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):  # Skip comments and empty lines
                    urls.append(url)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
    return urls

def prepare_dataset(malicious_file, suspicious_file):
    """
    Prepare complete dataset from malicious and suspicious URL files
    """
    print("="*60)
    print("DATASET PREPARATION FROM VIRUSTOTAL DATA")
    print("="*60)
    
    # Load URLs
    print("\n[1/4] Loading URLs...")
    malicious_urls = load_urls_from_file(malicious_file)
    suspicious_urls = load_urls_from_file(suspicious_file)
    
    print(f"  ✓ Loaded {len(malicious_urls)} malicious URLs")
    print(f"  ✓ Loaded {len(suspicious_urls)} suspicious URLs")
    
    # Generate safe URLs (we'll create synthetic safe URLs)
    print("\n[2/4] Generating safe URLs for balanced dataset...")
    safe_urls = [
        'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'reddit.com', 'netflix.com',
        'github.com', 'stackoverflow.com', 'microsoft.com', 'apple.com', 'yahoo.com',
        'bbc.com', 'cnn.com', 'nytimes.com', 'washingtonpost.com', 'theguardian.com',
        'medium.com', 'wordpress.com', 'blogger.com', 'tumblr.com', 'pinterest.com',
        'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com', 'homedepot.com',
        'espn.com', 'nba.com', 'nfl.com', 'foxnews.com', 'usatoday.com',
        'imdb.com', 'rottentomatoes.com', 'spotify.com', 'soundcloud.com', 'twitch.tv',
        'adobe.com', 'oracle.com', 'salesforce.com', 'dropbox.com', 'slack.com',
        'zoom.us', 'webex.com', 'indeed.com', 'glassdoor.com', 'monster.com',
        'booking.com', 'airbnb.com', 'expedia.com', 'tripadvisor.com', 'hotels.com',
        'craigslist.org', 'etsy.com', 'shopify.com', 'alibaba.com', 'aliexpress.com',
        'paypal.com', 'stripe.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
        'att.com', 'verizon.com', 'tmobile.com', 'sprint.com', 'comcast.com',
        'bing.com', 'duckduckgo.com', 'weather.com', 'accuweather.com', 'nasa.gov',
        'stanford.edu', 'mit.edu', 'harvard.edu', 'berkeley.edu', 'oxford.ac.uk',
        'mozilla.org', 'python.org', 'nodejs.org', 'angular.io', 'reactjs.org',
    ]
    
    # Balance dataset - use maximum available data
    num_samples = min(len(malicious_urls), len(suspicious_urls), len(safe_urls) * 40)
    num_samples = min(num_samples, 4000)  # Increased to 4000 per class for maximum learning
    
    print(f"  ✓ Using {num_samples} samples per class for balanced dataset")
    
    # Sample URLs
    malicious_sample = malicious_urls[:num_samples] if len(malicious_urls) >= num_samples else malicious_urls
    suspicious_sample = suspicious_urls[:num_samples] if len(suspicious_urls) >= num_samples else suspicious_urls
    safe_sample = (safe_urls * 20)[:num_samples]  # Repeat safe URLs to match count
    
    # Extract features
    print("\n[3/4] Extracting features from URLs...")
    X_malicious = []
    for i, url in enumerate(malicious_sample):
        features = extract_features_from_url(url)
        X_malicious.append(features)
        if (i + 1) % 100 == 0:
            print(f"  - Processed {i + 1}/{len(malicious_sample)} malicious URLs")
    
    X_suspicious = []
    for i, url in enumerate(suspicious_sample):
        features = extract_features_from_url(url)
        X_suspicious.append(features)
        if (i + 1) % 100 == 0:
            print(f"  - Processed {i + 1}/{len(suspicious_sample)} suspicious URLs")
    
    X_safe = []
    for i, url in enumerate(safe_sample):
        features = extract_features_from_url(url)
        X_safe.append(features)
    print(f"  - Processed {len(safe_sample)} safe URLs")
    
    # Combine dataset
    print("\n[4/4] Combining dataset...")
    X = np.array(X_malicious + X_suspicious + X_safe)
    y = np.array(
        [1] * len(X_malicious) +      # Malicious = 1
        [0] * len(X_suspicious) +     # Suspicious = 0
        [-1] * len(X_safe)            # Safe = -1
    )
    
    # Create DataFrame for better visualization
    feature_names = [
        'isIPInURL', 'isLongURL', 'isTinyURL', 'isAlphaNumericURL', 
        'isRedirectingURL', 'isHypenURL', 'isMultiDomainURL', 
        'isFaviconDomainUnidentical', 'isIllegalHttpsURL', 
        'isImgFromDifferentDomain', 'isAnchorFromDifferentDomain', 
        'isScLnkFromDifferentDomain', 'isFormActionInvalid', 
        'isMailToAvailable', 'isStatusBarTampered', 'isIframePresent'
    ]
    
    df = pd.DataFrame(X, columns=feature_names)
    df['label'] = y
    
    # Save dataset
    df.to_csv('website_dataset.csv', index=False)
    print(f"\n✓ Dataset saved to: website_dataset.csv")
    
    print("\n" + "="*60)
    print("DATASET SUMMARY")
    print("="*60)
    print(f"Total samples: {len(X)}")
    print(f"  - Malicious (1): {len(X_malicious)}")
    print(f"  - Suspicious (0): {len(X_suspicious)}")
    print(f"  - Safe (-1): {len(X_safe)}")
    print(f"\nFeatures: {len(feature_names)}")
    print(f"Shape: {X.shape}")
    
    # Show sample statistics
    print("\n" + "="*60)
    print("FEATURE STATISTICS")
    print("="*60)
    print(df.groupby('label').mean())
    
    return X, y, df

if __name__ == "__main__":
    # File paths
    malicious_file = 'virustotalresult_malicious.txt'
    suspicious_file = 'virustotalresult_suspicious.txt'
    
    # Prepare dataset
    X, y, df = prepare_dataset(malicious_file, suspicious_file)
    
    print("\n✓ Dataset preparation complete!")
    print("\nNext step: Run train_model.py to train the Random Forest classifier")
