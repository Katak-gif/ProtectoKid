# Quick Reference: Boost Accuracy to 80%+

## Current Status
✅ **Current**: 62% accuracy  
🎯 **Target**: 80%+ accuracy  
📊 **Gap**: Need +18 percentage points

## Why Low Malicious Detection (22%)?
The model is too conservative - it marks 68% of malicious sites as "suspicious" instead of "malicious". This is actually SAFER for users (they still get warnings), but lowers accuracy metrics.

---

## 🚀 Quick Wins (Get to 70% in 1 hour)

### 1. Run Advanced Training (RUNNING NOW)
```bash
python train_advanced.py
```
- ✅ Adds 5 engineered features
- ✅ Uses balanced class weights
- ✅ Tries ensemble if needed
- **Expected**: 68-72% accuracy

### 2. Adjust Decision Thresholds
In `content.js`, make the model more aggressive:

```javascript
// Current thresholds:
var maliciousThreshold = 0.25;
var suspiciousThreshold = 0.08;
var safeThreshold = 0.40;

// More aggressive (will increase malicious detection):
var maliciousThreshold = 0.15;  // Lower = more sensitive
var suspiciousThreshold = 0.12;
var safeThreshold = 0.50;
```

**Impact**: +5-10% accuracy by catching more malicious sites

---

## 📈 Medium Effort (Get to 75% in 1 day)

### 3. Collect More Data

**Current dataset**: 1,500 URLs (500 each)  
**Target**: 6,000+ URLs (2,000+ each)

#### Download PhishTank Data
```bash
# 1. Download from https://phishtank.org/developer_info.php
# 2. Extract URLs
python -c "
import json
with open('verified_online.json') as f:
    data = json.load(f)
    with open('phishtank_urls.txt', 'w') as out:
        for entry in data:
            out.write(entry['url'] + '\n')
"

# 3. Append to your malicious file
cat phishtank_urls.txt >> virustotalresult_malicious.txt

# 4. Re-train
python prepare_dataset.py
python train_advanced.py
```

#### Add More Safe URLs
Create `safe_urls_expanded.txt`:
```
# Top 500 legitimate websites
google.com, youtube.com, facebook.com, amazon.com, wikipedia.org
twitter.com, instagram.com, linkedin.com, reddit.com, netflix.com
github.com, stackoverflow.com, microsoft.com, apple.com, yahoo.com
... (add 485 more)
```

**Expected Impact**: +8-12% accuracy

---

## 🎯 High Effort (Get to 80%+ in 3-5 days)

### 4. Add Advanced Features

Create `advanced_features.py`:

```python
import tldextract
import math
from datetime import datetime
import whois

def calculate_url_entropy(url):
    """High randomness = suspicious"""
    prob = [url.count(c)/len(url) for c in set(url)]
    entropy = -sum(p * math.log2(p) for p in prob if p > 0)
    return 1 if entropy > 4.5 else -1

def get_digit_ratio(url):
    """Too many digits = suspicious"""
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    ratio = digits / (letters + 1)
    return 1 if ratio > 0.3 else -1

def get_special_char_ratio(url):
    """Too many special chars = suspicious"""
    special = sum(not c.isalnum() for c in url)
    ratio = special / len(url)
    return 1 if ratio > 0.4 else -1

def check_suspicious_tld(url):
    """Check for suspicious TLDs"""
    ext = tldextract.extract(url)
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.pw', '.top']
    return 1 if any(ext.suffix.endswith(tld.strip('.')) for tld in suspicious_tlds) else -1

def count_subdomains(url):
    """Many subdomains = suspicious"""
    ext = tldextract.extract(url)
    if not ext.subdomain:
        return -1
    count = len(ext.subdomain.split('.'))
    return 1 if count > 2 else (0 if count == 2 else -1)

def check_domain_age(url):
    """Young domains are suspicious"""
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                age = (datetime.now() - w.creation_date[0]).days
            else:
                age = (datetime.now() - w.creation_date).days
            return 1 if age < 365 else -1
        return 0
    except:
        return 0

# Add these to extract_features_from_url() in prepare_dataset.py
```

**Install dependencies**:
```bash
pip install tldextract python-whois
```

**Update prepare_dataset.py** to include these 6 new features (total: 22 features)

**Expected Impact**: +10-15% accuracy

---

## 🔬 Alternative: Use External APIs (80-90% accuracy)

Instead of training a model, use threat intelligence APIs:

### Google Safe Browsing API
```python
import requests

def check_google_safe_browsing(url):
    api_key = "YOUR_API_KEY"
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "protectokid",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    response = requests.post(api_url, json=payload)
    return response.json()
```

**Pros**: 90%+ accuracy, always up-to-date  
**Cons**: Requires API key, internet connection, costs money at scale

---

## 📊 Monitoring Progress

After each improvement, check:

```python
# Run this after training
python -c "
import pickle
import numpy as np
from sklearn.metrics import classification_report

# Load model and test data
model = pickle.load(open('random_forest_model_optimized.pkl', 'rb'))
# ... load test data ...

# Check per-class recall (most important!)
print('Target Metrics:')
print('Safe Recall: 80%+ ✓')
print('Suspicious Recall: 85%+')
print('Malicious Recall: 70%+ (currently 22%)')
"
```

---

## 🎯 Realistic Targets

| Intervention | Time | Expected Accuracy |
|--------------|------|-------------------|
| **Now** | - | 62% |
| + Advanced training | 30 min | 68-72% |
| + Threshold tuning | 15 min | 70-74% |
| + 2x more data | 2 hours | 72-76% |
| + 5x more data | 1 day | 75-80% |
| + Advanced features | 3 days | 78-85% |
| + API integration | 1 week | 85-95% |

---

## ⚡ Action Plan (Choose One)

### Path A: Quick & Practical (70-75%)
1. ✅ Run `train_advanced.py` (running now)
2. Tune thresholds in `content.js`
3. Add 1,000 more URLs to each class
4. **Time**: 3-4 hours
5. **Result**: 70-75% accuracy

### Path B: Thorough (75-80%)
1. ✅ Run `train_advanced.py`
2. Download PhishTank database (15,000+ malicious URLs)
3. Add 1,000+ safe URLs from Alexa Top Sites
4. Implement 6 advanced features from `advanced_features.py`
5. **Time**: 3-5 days
6. **Result**: 78-82% accuracy

### Path C: Production-Ready (85-95%)
1. Use Path B as foundation
2. Integrate Google Safe Browsing API
3. Add VirusTotal API as second check
4. Implement caching to reduce API calls
5. **Time**: 1-2 weeks
6. **Result**: 85-95% accuracy

---

## 🚨 Important Notes

### Don't Just Optimize Accuracy!
Current model:
- Safe: 80% recall ✓
- Suspicious: 84% recall ✓
- **Malicious: 22% recall** ❌ ← This is the problem!

**Focus on**: Increasing malicious recall from 22% to 70%+

### Why Malicious Recall is Low
- Model is too conservative
- Marks malicious as "suspicious" (68%)
- Need more diverse malicious training data

### Solution
1. **More malicious data** (most important!)
2. **Lower malicious threshold** (quick fix)
3. **Better features** (long-term solution)

---

## Next Steps

1. **Wait for current training to finish** (ensemble method running)
2. **Review results** - if 65-70%, proceed with data collection
3. **If still < 70%**, adjust thresholds in content.js
4. **Plan data collection** - aim for 3,000+ malicious URLs

**Remember**: 80% accuracy with good per-class balance is better than 90% accuracy with poor malicious detection! 🎯
