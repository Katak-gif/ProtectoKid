# GitHub Actions Setup for VirusTotal Training

This repository uses GitHub Actions to train the malicious website detection model using VirusTotal API in the cloud - **completely free and automatic!**

## 🚀 Setup Instructions

### Step 1: Push to GitHub

```powershell
# Initialize git (if not already done)
git init

# Add all files
git add .
git commit -m "Add VirusTotal training with GitHub Actions"

# Create repository on GitHub (https://github.com/new)
# Then push:
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

### Step 2: Add VirusTotal API Key as Secret

1. Go to your GitHub repository
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `VIRUSTOTAL_API_KEY`
5. Value: `bb2804cc562d56cc07bba805d7fe764fc89bbe9899979f758f47790c559509e5`
6. Click **Add secret**

### Step 3: Run the Workflow

1. Go to **Actions** tab in your repository
2. Click **Train Model with VirusTotal API** workflow
3. Click **Run workflow** button
4. Enter number of URLs per class (default: 20, max recommended: 500)
5. Click **Run workflow**

## 📊 What Happens

- ✅ Runs on GitHub's servers (no need for your computer to be on)
- ✅ Collects URLs from VirusTotal API with rate limiting
- ✅ Extracts 22 features from each URL
- ✅ Trains Random Forest model
- ✅ Uploads trained model as downloadable artifacts

## ⏱️ Expected Runtime

- **20 URLs/class** (60 total): ~15 minutes
- **50 URLs/class** (150 total): ~38 minutes
- **100 URLs/class** (300 total): ~75 minutes
- **500 URLs/class** (1500 total): ~6 hours (if you have premium API)

## 📥 Download Results

1. Go to **Actions** tab
2. Click on your completed workflow run
3. Scroll to **Artifacts** section
4. Download **trained-model-virustotal**
5. Extract and copy files to your Extension folder

## 🔄 Retraining

Just click **Run workflow** again anytime! You can:
- Use different number of URLs
- Retrain with updated VirusTotal data
- Run multiple times for comparison

## 💰 Cost

**Completely FREE!**
- GitHub Actions: 2,000 minutes/month free
- Each training run uses ~15-75 minutes depending on URLs

## ⚠️ Important Notes

- **Free VirusTotal API**: 4 requests/minute limit
- **GitHub Actions timeout**: 6 hours maximum
- **Artifacts retention**: 30 days (download within 30 days)
- For faster training, consider VirusTotal Premium API

## 🆘 Troubleshooting

**Workflow fails with API error:**
- Check your API key is correct in Secrets
- Verify VirusTotal API key is active

**Timeout after 6 hours:**
- Reduce number of URLs
- Or get VirusTotal Premium API (1000+ requests/minute)

**No artifacts uploaded:**
- Check the logs in Actions tab
- Workflow may have failed during collection
