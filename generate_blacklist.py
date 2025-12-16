import re
from urllib.parse import urlparse

# Read all malicious URLs
with open("virustotalresult_malicious.txt", "r", encoding="utf-8", errors="ignore") as f:
    urls = f.read().splitlines()

# Extract domains
domains = set()
for url in urls:
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        if domain and "." in domain:
            domains.add(domain)
    except:
        pass

# Write blacklist as JavaScript array
with open("malicious_blacklist.js", "w", encoding="utf-8") as f:
    f.write("// Auto-generated blacklist from 34K+ malicious URLs\n")
    f.write("const maliciousDomains = [\n")
    for domain in sorted(domains)[:1000]:  # Limit to 1000 for performance
        f.write(f"  \"{domain}\",\n")
    f.write("];\n")

print(f" Generated blacklist with {len(domains)} domains")
print(f" Saved top 1000 to malicious_blacklist.js")
