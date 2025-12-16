"""
Random Forest Training Script for Malicious Website Detection
This script trains a Random Forest classifier on website features
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
import json

# Sample dataset - Replace with your actual dataset
# Features: [isIPInURL, isLongURL, isTinyURL, isAlphaNumericURL, isRedirectingURL,
#            isHypenURL, isMultiDomainURL, isFaviconDomainUnidentical, isIllegalHttpsURL,
#            isImgFromDifferentDomain, isAnchorFromDifferentDomain, isScLnkFromDifferentDomain,
#            isFormActionInvalid, isMailToAvailable, isStatusBarTampered, isIframePresent]

def create_sample_dataset():
    """
    Load dataset from CSV file (created by prepare_dataset.py)
    Falls back to sample data if CSV doesn't exist
    """
    try:
        # Try to load from enhanced CSV first (22 features)
        print("Attempting to load dataset from CSV...")
        try:
            df = pd.read_csv('website_dataset_enhanced.csv')
            print(f"✓ Successfully loaded {len(df)} samples from ENHANCED CSV (22 features)")
        except FileNotFoundError:
            df = pd.read_csv('website_dataset.csv')
            print(f"✓ Successfully loaded {len(df)} samples from CSV (16 features)")
        
        X = df.iloc[:, :-1].values  # All columns except last
        y = df.iloc[:, -1].values   # Last column (labels)
        return X, y
    except FileNotFoundError:
        print("⚠ CSV file not found. Using sample dataset.")
        print("  Run 'python prepare_dataset.py' first to use real VirusTotal data.")
        
        # Fallback: Malicious websites (label = 1)
        malicious_samples = [
            [1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            [1, 1, -1, -1, 1, 1, 1, 1, -1, 1, 1, 1, 1, -1, 1, 1],
            [1, 1, -1, 1, 1, -1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1],
            [-1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1],
            [1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1],
            [1, 0, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1],
            [1, 1, -1, 1, 1, 1, -1, 1, 1, 1, 0, 1, 1, 1, 1, 1],
            [-1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            [1, 1, -1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1],
            [1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1],
        ]
        
        # Suspicious websites (label = 0)
        suspicious_samples = [
            [-1, 0, -1, -1, 1, -1, -1, 1, -1, 0, 0, 0, 1, -1, -1, 1],
            [-1, 0, -1, 1, -1, -1, -1, 1, -1, 0, 1, 0, -1, -1, -1, 1],
            [-1, 1, -1, -1, 1, -1, -1, -1, -1, 0, 0, 1, 1, -1, -1, -1],
            [-1, 0, -1, 1, -1, 1, -1, 1, -1, 1, 0, 0, -1, 1, -1, 1],
            [-1, 0, -1, -1, 1, -1, 1, 1, -1, 0, 0, 0, 1, -1, -1, -1],
            [-1, 1, -1, 1, -1, -1, -1, 1, -1, 0, 1, 0, 1, -1, -1, 1],
            [-1, 0, -1, -1, 1, -1, -1, -1, 1, 0, 0, 0, -1, 1, -1, 1],
            [1, 0, -1, -1, -1, -1, -1, 1, -1, 0, 0, 1, 1, -1, -1, -1],
        ]
        
        # Safe websites (label = -1)
        safe_samples = [
            [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1],
            [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1],
            [-1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1],
            [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1],
            [-1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1],
            [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1],
            [-1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1, -1],
            [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1],
            [-1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1],
            [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1],
        ]
        
        # Combine all samples
        X = np.array(malicious_samples + suspicious_samples + safe_samples)
        y = np.array([1]*len(malicious_samples) + [0]*len(suspicious_samples) + [-1]*len(safe_samples))
        
        return X, y

def train_random_forest(X, y):
    """
    Train Random Forest classifier with optimized parameters
    """
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("Training Random Forest Classifier...")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    print(f"Number of features: {X.shape[1]}")
    
    # Initialize Random Forest with optimized parameters
    rf_model = RandomForestClassifier(
        n_estimators=200,          # Number of trees
        max_depth=10,              # Maximum depth of trees
        min_samples_split=2,       # Minimum samples to split a node
        min_samples_leaf=1,        # Minimum samples at leaf node
        random_state=42,
        n_jobs=-1                  # Use all CPU cores
    )
    
    # Train the model
    rf_model.fit(X_train, y_train)
    
    # Predictions
    y_pred = rf_model.predict(X_test)
    
    # Evaluate the model
    print("\n" + "="*50)
    print("MODEL EVALUATION")
    print("="*50)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # Cross-validation score
    cv_scores = cross_val_score(rf_model, X, y, cv=5)
    print(f"Cross-validation scores: {cv_scores}")
    print(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Safe (-1)', 'Suspicious (0)', 'Malicious (1)']))
    
    # Confusion matrix
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    feature_names = [
        'isIPInURL', 'isLongURL', 'isTinyURL', 'isAlphaNumericURL', 
        'isRedirectingURL', 'isHypenURL', 'isMultiDomainURL', 
        'isFaviconDomainUnidentical', 'isIllegalHttpsURL', 
        'isImgFromDifferentDomain', 'isAnchorFromDifferentDomain', 
        'isScLnkFromDifferentDomain', 'isFormActionInvalid', 
        'isMailToAvailable', 'isStatusBarTampered', 'isIframePresent',
        'urlEntropy', 'digitRatio', 'specialCharCount', 'suspiciousTLD', 
        'subdomainDepth', 'pathLength'
    ]
    
    # Handle dynamic feature count
    if len(rf_model.feature_importances_) != len(feature_names):
        feature_names = [f'feature_{i}' for i in range(len(rf_model.feature_importances_))]
    
    print("\n" + "="*50)
    print("FEATURE IMPORTANCE")
    print("="*50)
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(feature_importance.to_string(index=False))
    
    return rf_model, feature_importance

def export_model_for_javascript(rf_model, feature_importance):
    """
    Export model in a format usable by JavaScript
    For Random Forest, we'll create a simplified decision function
    """
    print("\n" + "="*50)
    print("EXPORTING MODEL FOR JAVASCRIPT")
    print("="*50)
    
    # Save the full model
    with open('random_forest_model.pkl', 'wb') as f:
        pickle.dump(rf_model, f)
    print("✓ Full model saved to: random_forest_model.pkl")
    
    # Export feature importance as weights (simplified approach)
    # For a lightweight JS implementation, we use feature importance as weights
    weights = feature_importance.sort_values('feature')['importance'].values.tolist()
    
    weights_js = ', '.join([f"{w:.8e}" for w in weights])
    
    print("\n✓ JavaScript-compatible weights (feature importance):")
    print(f"[{weights_js}]")
    
    # Save to JSON
    export_data = {
        'model_type': 'RandomForest',
        'n_estimators': rf_model.n_estimators,
        'n_features': rf_model.n_features_in_,
        'classes': rf_model.classes_.tolist(),
        'feature_importance': weights,
        'feature_names': [
            'isIPInURL', 'isLongURL', 'isTinyURL', 'isAlphaNumericURL', 
            'isRedirectingURL', 'isHypenURL', 'isMultiDomainURL', 
            'isFaviconDomainUnidentical', 'isIllegalHttpsURL', 
            'isImgFromDifferentDomain', 'isAnchorFromDifferentDomain', 
            'isScLnkFromDifferentDomain', 'isFormActionInvalid', 
            'isMailToAvailable', 'isStatusBarTampered', 'isIframePresent'
        ],
        'weights_for_js': weights
    }
    
    with open('model_export.json', 'w') as f:
        json.dump(export_data, f, indent=2)
    print("✓ Model metadata saved to: model_export.json")
    
    return weights

def test_predictions(rf_model):
    """
    Test the model with some sample cases
    """
    print("\n" + "="*50)
    print("TESTING SAMPLE PREDICTIONS")
    print("="*50)
    
    test_cases = {
        'Highly Malicious Site': [1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        'Suspicious Site': [-1, 0, -1, 1, 1, -1, -1, 1, -1, 0, 0, 0, 1, -1, -1, 1],
        'Safe Site': [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1],
    }
    
    for name, features in test_cases.items():
        prediction = rf_model.predict([features])[0]
        probabilities = rf_model.predict_proba([features])[0]
        
        label = {-1: 'Safe', 0: 'Suspicious', 1: 'Malicious'}[prediction]
        print(f"\n{name}:")
        print(f"  Prediction: {prediction} ({label})")
        print(f"  Probabilities: Safe={probabilities[0]:.3f}, Suspicious={probabilities[1]:.3f}, Malicious={probabilities[2]:.3f}")

if __name__ == "__main__":
    print("="*50)
    print("RANDOM FOREST TRAINING FOR MALICIOUS WEBSITE DETECTION")
    print("="*50)
    
    # Create or load dataset
    print("\nLoading dataset...")
    X, y = create_sample_dataset()
    print(f"✓ Dataset loaded: {len(X)} samples")
    print(f"  - Malicious: {sum(y == 1)} samples")
    print(f"  - Suspicious: {sum(y == 0)} samples")
    print(f"  - Safe: {sum(y == -1)} samples")
    
    # Train model
    rf_model, feature_importance = train_random_forest(X, y)
    
    # Export for JavaScript
    weights = export_model_for_javascript(rf_model, feature_importance)
    
    # Test predictions
    test_predictions(rf_model)
    
    print("\n" + "="*50)
    print("TRAINING COMPLETE!")
    print("="*50)
    print("\nNext steps:")
    print("1. Review the model performance above")
    print("2. Copy the weights to content.js")
    print("3. Test the extension with real websites")
    print("\nFiles created:")
    print("  - random_forest_model.pkl (Python model)")
    print("  - model_export.json (Model metadata)")
