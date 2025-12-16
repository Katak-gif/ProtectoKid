# Random Forest Model for Malicious Website Detection

## Overview
This extension uses a **Random Forest classifier** to detect malicious websites based on 16 extracted features from web pages.

## Model Performance
- **Algorithm**: Random Forest Classifier
- **Training Accuracy**: 100%
- **Cross-Validation Score**: 100% (5-fold CV)
- **Number of Trees**: 100
- **Max Depth**: 10

## Features Used (16 Total)

The model analyzes the following website characteristics:

1. **isIPInURL** - Checks if the URL contains an IP address instead of domain name
2. **isLongURL** - Detects abnormally long URLs (>75 characters)
3. **isTinyURL** - Identifies very short URLs (<20 characters)
4. **isAlphaNumericURL** - Checks for '@' symbol in URL
5. **isRedirectingURL** - Detects multiple redirects
6. **isHypenURL** - Checks for hyphens in domain name
7. **isMultiDomainURL** - Identifies URLs with multiple subdomains
8. **isFaviconDomainUnidentical** - Favicon loaded from different domain
9. **isIllegalHttpsURL** - Checks for HTTPS misuse
10. **isImgFromDifferentDomain** - Images loaded from external domains
11. **isAnchorFromDifferentDomain** - Links pointing to external domains
12. **isScLnkFromDifferentDomain** - Scripts/stylesheets from external domains
13. **isFormActionInvalid** - Form submission to suspicious URLs
14. **isMailToAvailable** - Presence of mailto links
15. **isStatusBarTampered** - JavaScript status bar manipulation
16. **isIframePresent** - Presence of iframes

## Feature Importance Ranking

Based on the trained Random Forest model:

| Rank | Feature | Importance | Description |
|------|---------|------------|-------------|
| 1 | isImgFromDifferentDomain | 18.92% | Most important indicator |
| 2 | isAnchorFromDifferentDomain | 16.47% | External links detection |
| 3 | isMultiDomainURL | 9.72% | Multiple subdomain detection |
| 4 | isScLnkFromDifferentDomain | 7.82% | External resources |
| 5 | isStatusBarTampered | 7.80% | JavaScript manipulation |
| 6 | isFaviconDomainUnidentical | 5.94% | Favicon source check |
| 7 | isIllegalHttpsURL | 5.88% | HTTPS misuse |
| 8 | isRedirectingURL | 5.72% | Redirect detection |
| 9 | isLongURL | 4.30% | URL length check |
| 10 | isAlphaNumericURL | 4.28% | Special character check |
| 11 | isHypenURL | 4.29% | Hyphen detection |
| 12 | isIPInURL | 3.94% | IP address check |
| 13 | isIframePresent | 2.19% | Iframe detection |
| 14 | isMailToAvailable | 1.76% | Mailto links |
| 15 | isFormActionInvalid | 0.97% | Form validation |
| 16 | isTinyURL | 0.00% | Short URL check |

## Classification Levels

The model classifies websites into three categories:

- **Safe (-1)**: No suspicious indicators detected
- **Suspicious (0)**: Some warning signs present, proceed with caution
- **Malicious (1)**: High probability of being unsafe

## Training the Model

### Prerequisites
```bash
pip install -r requirements.txt
```

Required packages:
- numpy >= 1.21.0
- pandas >= 1.3.0
- scikit-learn >= 1.0.0

### Running Training Script
```bash
python train_model.py
```

This will:
1. Load the training dataset (28 samples)
2. Train the Random Forest classifier
3. Evaluate model performance
4. Export weights for JavaScript
5. Save the trained model to `random_forest_model.pkl`
6. Generate `model_export.json` with model metadata

## Using Your Own Dataset

To train with your own data, modify the `create_sample_dataset()` function in `train_model.py`:

```python
def create_sample_dataset():
    # Load your CSV or data file
    data = pd.read_csv('your_dataset.csv')
    X = data.iloc[:, :-1].values  # Features
    y = data.iloc[:, -1].values   # Labels (-1, 0, 1)
    return X, y
```

Expected format:
- Each row represents a website
- Columns 1-16: Feature values (-1, 0, or 1)
- Last column: Label (-1 = safe, 0 = suspicious, 1 = malicious)

## Model Files

- `train_model.py` - Training script
- `random_forest_model.pkl` - Trained Random Forest model (Python)
- `model_export.json` - Model metadata and weights
- `requirements.txt` - Python dependencies
- `content.js` - JavaScript implementation with trained weights

## How It Works in the Extension

1. **Feature Extraction**: When you visit a website, the extension extracts 16 features from the page
2. **Prediction**: Features are passed through the Random Forest-based prediction function
3. **Classification**: The website is classified as Safe, Suspicious, or Malicious
4. **Alert Display**: A modal shows the security assessment with appropriate warnings

## Improving the Model

To improve accuracy:

1. **Collect More Data**: Add more labeled website samples
2. **Adjust Hyperparameters**: Modify `n_estimators`, `max_depth` in `train_model.py`
3. **Feature Engineering**: Add new features or modify existing ones
4. **Balance Dataset**: Ensure equal representation of all classes
5. **Cross-Validation**: Test with different train-test splits

## Testing the Model

Sample test cases are included in the training script:

```python
# Highly Malicious Site
[1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
→ Prediction: Malicious (100% confidence)

# Suspicious Site  
[-1, 0, -1, 1, 1, -1, -1, 1, -1, 0, 0, 0, 1, -1, -1, 1]
→ Prediction: Suspicious (94% confidence)

# Safe Site
[-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
→ Prediction: Safe (100% confidence)
```

## Extension Integration

The trained weights are automatically integrated into `content.js`. The prediction function uses:
- Feature importance scores as weights
- Threshold-based classification
- Suspicious feature counting for edge cases

## Troubleshooting

**Low accuracy?**
- Increase training data
- Balance the dataset classes
- Adjust decision thresholds in `content.js`

**False positives?**
- Increase malicious threshold
- Add more safe website samples
- Review feature extraction logic

**Not detecting malicious sites?**
- Lower malicious threshold
- Add more malicious samples
- Check feature importance rankings

## License
MIT License - Feel free to modify and improve!

## Contributing
To contribute improvements:
1. Collect more labeled website data
2. Test with real-world websites
3. Share your trained model weights
4. Report accuracy metrics
