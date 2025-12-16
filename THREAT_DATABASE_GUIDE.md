# Threat Database Update Guide

## Overview
Your extension now uses a **hybrid detection system**:
1. **Cloud-hosted threat database** (blacklist/whitelist) - checked first
2. **Local ML model** (Random Forest) - used if URL not in database

This gives you **real-time protection** without needing a server!

## How It Works

```
User visits URL
    ↓
Extension fetches threat-database.json from GitHub
    ↓
Check blacklist → Instant block if found
    ↓
Check whitelist → Instant safe if found
    ↓
Not in database? → Run ML prediction
    ↓
Show result to user
```

## Setup Instructions

### Step 1: Host the Threat Database (FREE on GitHub)

1. The `threat-database.json` file is already in your repo
2. Push it to GitHub:
   ```powershell
   git add threat-database.json
   git commit -m "Add threat database for real-time updates"
   git push
   ```

3. Access URL will be:
   ```
   https://raw.githubusercontent.com/Katak-gif/ProtectoKid/main/threat-database.json
   ```

4. The extension already points to this URL in `content.js` (line ~9)

### Step 2: Enable GitHub Pages (Optional - for better caching)

1. Go to your repo: https://github.com/Katak-gif/ProtectoKid
2. Settings → Pages
3. Source: Deploy from branch `main`
4. Folder: `/ (root)`
5. Save

Then update the URL in `content.js` to:
```javascript
const url = 'https://katak-gif.github.io/ProtectoKid/threat-database.json';
```

## Updating the Threat Database

### Daily/Weekly Updates

**Add Malicious Sites:**
```json
"blacklist": [
  "example-phishing-site.tk",
  "malicious-url.ml",
  "new-phishing-site-2025.ga"  ← Add here
]
```

**Add Safe Sites:**
```json
"whitelist": [
  "google.com",
  "youtube.com",
  "your-trusted-site.com"  ← Add here
]
```

**Update version & date:**
```json
"version": "1.0.1",
"lastUpdated": "2025-12-18T10:00:00Z"
```

**Push changes:**
```powershell
git add threat-database.json
git commit -m "Update threat database - added 50 new malicious sites"
git push
```

**Done!** All users get the update automatically (fetched on each page load).

## Automated Updates (Advanced)

### Option A: GitHub Actions (Auto-update from VirusTotal)

Create `.github/workflows/update-threats.yml`:
```yaml
name: Update Threat Database
on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install requests
      - name: Fetch latest threats from VirusTotal
        env:
          VT_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
        run: python scripts/update_threats.py
      - name: Commit changes
        run: |
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add threat-database.json
          git commit -m "Auto-update threat database" || exit 0
          git push
```

### Option B: Manual Updates from VirusTotal

Use the existing `train_with_virustotal_api.py` script to fetch latest URLs, then update the JSON manually.

## Monitoring

- Check GitHub repo for the file: https://github.com/Katak-gif/ProtectoKid/blob/main/threat-database.json
- View raw file: https://raw.githubusercontent.com/Katak-gif/ProtectoKid/main/threat-database.json
- Test in extension: Open any site, check browser console for `[ProtectoKid] Threat database loaded`

## Benefits

✅ **Real-time protection** - Update blacklist anytime, no extension republish needed  
✅ **Free hosting** - GitHub hosts the file for free  
✅ **Fast** - Database checked first, ML only runs if needed  
✅ **No server** - No maintenance, no costs  
✅ **Automatic** - Users get updates on every page load  
✅ **Flexible** - Add sources manually or automate with scripts  

## Troubleshooting

**Database not loading?**
- Check browser console for errors
- Verify the URL is accessible: https://raw.githubusercontent.com/Katak-gif/ProtectoKid/main/threat-database.json
- Make sure CORS is enabled (GitHub raw URLs allow CORS by default)

**Updates not appearing?**
- Clear browser cache
- Restart Chrome
- Check the `lastUpdated` timestamp in the JSON file

**Too many requests?**
- GitHub has rate limits (60/hour for unauthenticated)
- Extension caches the database per tab/session
- For higher limits, authenticate the fetch request with a GitHub token

## Next Steps

1. **Push the threat-database.json** to GitHub
2. **Test** by loading a website and checking console
3. **Set up automated updates** (optional)
4. **Monitor** and add new threats as you discover them

Your extension now has real-time threat intelligence! 🛡️
