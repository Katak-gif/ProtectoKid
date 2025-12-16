"""
Train model using VirusTotal API to get real-time threat intelligence
Requires VirusTotal API key: https://www.virustotal.com/gui/my-apikey
"""

import requests
import time
import json
import pandas as pd
from prepare_dataset_enhanced import extract_features_from_url_enhanced

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = "bb2804cc562d56cc07bba805d7fe764fc89bbe9899979f758f47790c559509e5"  # Replace with your actual API key
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls"

def check_url_virustotal(url):
    """
    Check a URL using VirusTotal API
    Returns: (classification, malicious_count, suspicious_count)
    classification: -1 (safe), 0 (suspicious), 1 (malicious)
    """
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    # Submit URL for scanning
    try:
        # First, encode URL
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Get URL report
        response = requests.get(
            f"{VIRUSTOTAL_API_URL}/{url_id}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            
            # Classification logic
            if malicious >= 3:  # 3+ engines flag as malicious
                return 1, malicious, suspicious
            elif suspicious >= 2 or malicious >= 1:  # Suspicious
                return 0, malicious, suspicious
            else:  # Safe
                return -1, malicious, suspicious
        
        elif response.status_code == 404:
            # URL not in database, assume safe for now
            return -1, 0, 0
        
        else:
            print(f"API Error {response.status_code}: {response.text}")
            return None, 0, 0
            
    except Exception as e:
        print(f"Error checking {url}: {e}")
        return None, 0, 0

def collect_urls_from_virustotal(num_urls=100):
    """
    Collect URLs and their classifications from VirusTotal
    Note: Free API has rate limits (4 requests/minute)
    """
    # Read existing URLs from files
    with open('virustotalresult_malicious.txt', 'r') as f:
        malicious_urls = [line.strip() for line in f if line.strip()][:num_urls]
    
    with open('virustotalresult_suspicious.txt', 'r') as f:
        suspicious_urls = [line.strip() for line in f if line.strip()][:num_urls]
    
    # Safe URLs (common legitimate sites)
    safe_urls = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
        'wikipedia.org', 'twitter.com', 'instagram.com', 'linkedin.com',
        'reddit.com', 'netflix.com', 'github.com', 'microsoft.com',
        'apple.com', 'stackoverflow.com', 'cnn.com', 'bbc.com',
        'nytimes.com', 'ebay.com', 'walmart.com', 'imdb.com'
    ] * (num_urls // 20)
    
    dataset = []
    
    print(f"\n{'='*60}")
    print("COLLECTING DATA FROM VIRUSTOTAL API")
    print(f"{'='*60}\n")
    print("⚠️  Free API Limit: 4 requests/minute")
    print(f"⚠️  Total URLs to check: {len(malicious_urls) + len(suspicious_urls) + len(safe_urls)}")
    print(f"⚠️  Estimated time: {((len(malicious_urls) + len(suspicious_urls) + len(safe_urls)) / 4):.0f} minutes\n")
    
    # Process malicious URLs
    print("[1/3] Verifying malicious URLs...")
    for i, url in enumerate(malicious_urls, 1):
        if not url.startswith('http'):
            url = 'http://' + url
        
        classification, mal_count, susp_count = check_url_virustotal(url)
        
        if classification is not None:
            features = extract_features_from_url_enhanced(url)
            features.append(classification)
            dataset.append(features)
            print(f"  [{i}/{len(malicious_urls)}] {url[:50]:<50} → {'Malicious' if classification == 1 else 'Suspicious' if classification == 0 else 'Safe'} (VT: {mal_count}M/{susp_count}S)")
        
        # Rate limiting: 4 requests per minute
        if i % 4 == 0:
            print("  ⏳ Rate limit: waiting 60 seconds...")
            time.sleep(60)
    
    # Process suspicious URLs
    print(f"\n[2/3] Verifying suspicious URLs...")
    for i, url in enumerate(suspicious_urls, 1):
        if not url.startswith('http'):
            url = 'http://' + url
        
        classification, mal_count, susp_count = check_url_virustotal(url)
        
        if classification is not None:
            features = extract_features_from_url_enhanced(url)
            features.append(classification)
            dataset.append(features)
            print(f"  [{i}/{len(suspicious_urls)}] {url[:50]:<50} → {'Malicious' if classification == 1 else 'Suspicious' if classification == 0 else 'Safe'} (VT: {mal_count}M/{susp_count}S)")
        
        if i % 4 == 0:
            print("  ⏳ Rate limit: waiting 60 seconds...")
            time.sleep(60)
    
    # Process safe URLs
    print(f"\n[3/3] Verifying safe URLs...")
    for i, url in enumerate(safe_urls, 1):
        if not url.startswith('http'):
            url = 'http://' + url
        
        classification, mal_count, susp_count = check_url_virustotal(url)
        
        if classification is not None:
            features = extract_features_from_url_enhanced(url)
            features.append(classification)
            dataset.append(features)
            print(f"  [{i}/{len(safe_urls)}] {url[:50]:<50} → {'Malicious' if classification == 1 else 'Suspicious' if classification == 0 else 'Safe'} (VT: {mal_count}M/{susp_count}S)")
        
        if i % 4 == 0:
            print("  ⏳ Rate limit: waiting 60 seconds...")
            time.sleep(60)
    
    return dataset

def save_virustotal_dataset(dataset, filename='website_dataset_virustotal.csv'):
    """Save dataset to CSV"""
    columns = [
        'isIPInURL', 'isLongURL', 'isTinyURL', 'isAlphaNumericURL', 'isRedirectingURL',
        'isHypenURL', 'isMultiDomainURL', 'isFaviconDomainUnidentical', 'isIllegalHttpsURL',
        'isImgFromDifferentDomain', 'isAnchorFromDifferentDomain', 'isScLnkFromDifferentDomain',
        'isFormActionInvalid', 'isMailToAvailable', 'isStatusBarTampered', 'isIframePresent',
        'urlEntropy', 'digitRatio', 'specialCharCount', 'suspiciousTLD', 'subdomainDepth', 
        'pathLength', 'label'
    ]
    
    df = pd.DataFrame(dataset, columns=columns)
    df.to_csv(filename, index=False)
    
    print(f"\n{'='*60}")
    print("DATASET SAVED")
    print(f"{'='*60}")
    print(f"✓ Filename: {filename}")
    print(f"✓ Total samples: {len(dataset)}")
    print(f"✓ Malicious: {len(df[df['label'] == 1])}")
    print(f"✓ Suspicious: {len(df[df['label'] == 0])}")
    print(f"✓ Safe: {len(df[df['label'] == -1])}")
    print(f"\n✅ Next step: Update train_model.py to use '{filename}'")

if __name__ == "__main__":
    # Check if API key is set
    if VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE":
        print("\n❌ ERROR: Please set your VirusTotal API key!")
        print("\n📌 How to get API key:")
        print("   1. Go to https://www.virustotal.com/")
        print("   2. Sign up/Login")
        print("   3. Go to https://www.virustotal.com/gui/my-apikey")
        print("   4. Copy your API key")
        print("   5. Replace 'YOUR_API_KEY_HERE' in this file\n")
        exit(1)
    
    # Collect data (start small due to rate limits)
    num_urls_per_class = 20  # Start with 20 URLs per class (60 total)
    print(f"\n⚠️  Starting with {num_urls_per_class} URLs per class")
    print("⚠️  You can increase this after verifying it works\n")
    
    dataset = collect_urls_from_virustotal(num_urls=num_urls_per_class)
    
    if dataset:
        save_virustotal_dataset(dataset)
    else:
        print("\n❌ No data collected. Check your API key and internet connection.")
