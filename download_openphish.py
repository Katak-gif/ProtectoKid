import requests

print("Downloading from OpenPhish (no registration required)...")
print("This provides active phishing URLs updated hourly")

try:
    # OpenPhish provides a simple text file of URLs
    url = 'https://openphish.com/feed.txt'
    response = requests.get(url, timeout=30)
    
    if response.status_code == 200:
        urls = response.text.strip().split('\n')
        print(f"✓ Downloaded {len(urls)} phishing URLs")
        
        # Append to malicious file
        print("\nAdding to virustotalresult_malicious.txt...")
        with open('virustotalresult_malicious.txt', 'a', encoding='utf-8') as f:
            for url in urls:
                if url.strip():
                    f.write(url.strip() + '\n')
        
        print(f"✓ Successfully added {len(urls)} malicious URLs!")
        
        # Check total count
        with open('virustotalresult_malicious.txt', 'r', encoding='utf-8') as f:
            total = len(f.readlines())
        
        print(f"\n📊 Total malicious URLs now: {total}")
        print("\n✅ Next steps:")
        print("   1. python prepare_dataset.py")
        print("   2. python train_advanced.py")
        
    else:
        print(f"✗ Error: Status code {response.status_code}")
        print("Try again later or use manual download")
        
except Exception as e:
    print(f"✗ Error: {e}")
    print("\nAlternative: URLhaus (no auth)")
    print("URL: https://urlhaus.abuse.ch/downloads/csv_recent/")
