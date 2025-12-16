"""
Advanced Training Script with Techniques to Achieve 80%+ Accuracy
This script implements multiple strategies to improve model performance
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
import pickle
import json

def load_and_enhance_dataset():
    """
    Load dataset and add engineered features
    """
    print("="*60)
    print("LOADING AND ENHANCING DATASET")
    print("="*60)
    
    # Load base dataset
    df = pd.read_csv('website_dataset.csv')
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values
    
    print(f"✓ Loaded {len(X)} samples")
    print(f"  Original features: {X.shape[1]}")
    
    # Feature engineering: Create interaction features
    print("\n[Feature Engineering]")
    
    # Add feature combinations that might be important
    feature_names = [
        'isIPInURL', 'isLongURL', 'isTinyURL', 'isAlphaNumericURL', 
        'isRedirectingURL', 'isHypenURL', 'isMultiDomainURL', 
        'isFaviconDomainUnidentical', 'isIllegalHttpsURL', 
        'isImgFromDifferentDomain', 'isAnchorFromDifferentDomain', 
        'isScLnkFromDifferentDomain', 'isFormActionInvalid', 
        'isMailToAvailable', 'isStatusBarTampered', 'isIframePresent'
    ]
    
    df_features = pd.DataFrame(X, columns=feature_names)
    
    # Create interaction features
    # 1. Suspicious domain indicators (combining related features)
    df_features['suspiciousDomain'] = (
        (df_features['isHypenURL'] == 1).astype(int) + 
        (df_features['isMultiDomainURL'] == 1).astype(int) +
        (df_features['isFaviconDomainUnidentical'] == 1).astype(int)
    )
    
    # 2. External resource indicators
    df_features['externalResources'] = (
        (df_features['isImgFromDifferentDomain'] == 1).astype(int) +
        (df_features['isAnchorFromDifferentDomain'] == 1).astype(int) +
        (df_features['isScLnkFromDifferentDomain'] == 1).astype(int)
    )
    
    # 3. Phishing indicators
    df_features['phishingIndicators'] = (
        (df_features['isFormActionInvalid'] == 1).astype(int) +
        (df_features['isStatusBarTampered'] == 1).astype(int) +
        (df_features['isIframePresent'] == 1).astype(int)
    )
    
    # 4. URL structure issues
    df_features['urlStructureIssues'] = (
        (df_features['isIPInURL'] == 1).astype(int) +
        (df_features['isRedirectingURL'] == 1).astype(int) +
        (df_features['isAlphaNumericURL'] == 1).astype(int)
    )
    
    # 5. Extreme length indicator (both very short and very long)
    df_features['extremeLength'] = (
        ((df_features['isTinyURL'] == 1).astype(int)) + 
        ((df_features['isLongURL'] == 1).astype(int))
    )
    
    X_enhanced = df_features.values
    
    print(f"✓ Added {X_enhanced.shape[1] - X.shape[1]} engineered features")
    print(f"  Total features: {X_enhanced.shape[1]}")
    
    return X_enhanced, y, df_features.columns.tolist()

def handle_class_imbalance(X, y):
    """
    Apply techniques to handle any class imbalance
    """
    from collections import Counter
    
    class_counts = Counter(y)
    print("\n[Class Distribution]")
    for label, count in sorted(class_counts.items()):
        label_name = {-1: 'Safe', 0: 'Suspicious', 1: 'Malicious'}[label]
        print(f"  {label_name} ({label}): {count} samples ({count/len(y)*100:.1f}%)")
    
    # If imbalanced, we can use SMOTE or class weights
    # For now, we'll use class weights in the classifier
    return X, y

def optimize_hyperparameters(X_train, y_train):
    """
    Use GridSearchCV to find optimal hyperparameters
    """
    print("\n[Hyperparameter Optimization]")
    print("Searching for optimal parameters (this may take a few minutes)...")
    
    # Define parameter grid
    param_grid = {
        'n_estimators': [150, 200, 250],
        'max_depth': [10, 15, 20, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'max_features': ['sqrt', 'log2', None]
    }
    
    # Smaller grid for faster testing
    param_grid_fast = {
        'n_estimators': [200, 250],
        'max_depth': [15, 20],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
        'max_features': ['sqrt', None]
    }
    
    rf = RandomForestClassifier(random_state=42, n_jobs=-1, class_weight='balanced')
    
    # Use 3-fold CV for speed
    grid_search = GridSearchCV(
        rf, param_grid_fast, cv=3, scoring='accuracy', 
        verbose=1, n_jobs=-1
    )
    
    grid_search.fit(X_train, y_train)
    
    print(f"\n✓ Best parameters: {grid_search.best_params_}")
    print(f"✓ Best CV score: {grid_search.best_score_:.4f}")
    
    return grid_search.best_estimator_

def train_ensemble_model(X_train, y_train):
    """
    Train an ensemble of multiple models for better accuracy
    """
    print("\n[Training Ensemble Model]")
    
    # Random Forest
    rf = RandomForestClassifier(
        n_estimators=250,
        max_depth=20,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features='sqrt',
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    # Gradient Boosting
    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=10,
        random_state=42
    )
    
    # Voting Classifier (combines both)
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('gb', gb)],
        voting='soft',  # Use probability-based voting
        n_jobs=-1
    )
    
    print("Training ensemble (Random Forest + Gradient Boosting)...")
    ensemble.fit(X_train, y_train)
    
    return ensemble

def train_advanced_model(X, y, feature_names, use_optimization=False, use_ensemble=False):
    """
    Train model with advanced techniques
    """
    print("\n" + "="*60)
    print("ADVANCED MODEL TRAINING")
    print("="*60)
    
    # Split data with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    
    # Choose training method
    if use_ensemble:
        model = train_ensemble_model(X_train, y_train)
        model_type = "Ensemble (RF + GB)"
    elif use_optimization:
        model = optimize_hyperparameters(X_train, y_train)
        model_type = "Optimized Random Forest"
    else:
        # Default: Well-tuned Random Forest with balanced class weights
        print("\n[Training Random Forest with Balanced Class Weights]")
        model = RandomForestClassifier(
            n_estimators=250,
            max_depth=20,
            min_samples_split=2,
            min_samples_leaf=1,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'  # Important for handling class imbalance
        )
        model.fit(X_train, y_train)
        model_type = "Random Forest (Balanced)"
    
    # Evaluate
    y_pred = model.predict(X_test)
    
    print("\n" + "="*60)
    print("MODEL EVALUATION")
    print("="*60)
    print(f"Model Type: {model_type}")
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n✓ Test Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # Cross-validation
    cv_scores = cross_val_score(model, X, y, cv=5, n_jobs=-1)
    print(f"✓ CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    print(f"  CV Scores: {[f'{s:.3f}' for s in cv_scores]}")
    
    # Detailed metrics
    print("\n" + "-"*60)
    print("Classification Report:")
    print("-"*60)
    print(classification_report(y_test, y_pred, 
                                target_names=['Safe (-1)', 'Suspicious (0)', 'Malicious (1)']))
    
    print("\n" + "-"*60)
    print("Confusion Matrix:")
    print("-"*60)
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    # Calculate per-class accuracy
    print("\nPer-Class Accuracy:")
    for i, label in enumerate([-1, 0, 1]):
        class_acc = cm[i, i] / cm[i, :].sum()
        label_name = {-1: 'Safe', 0: 'Suspicious', 1: 'Malicious'}[label]
        print(f"  {label_name}: {class_acc:.2%}")
    
    # Feature importance (if Random Forest)
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    elif hasattr(model, 'estimators_'):
        # For ensemble, average the importances
        importances = np.mean([est.feature_importances_ for est in model.estimators_], axis=0)
    else:
        importances = None
    
    if importances is not None:
        print("\n" + "="*60)
        print("TOP 10 FEATURE IMPORTANCE")
        print("="*60)
        feature_importance = pd.DataFrame({
            'feature': feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print(feature_importance.head(10).to_string(index=False))
    
    return model, accuracy, feature_importance if importances is not None else None

def export_for_javascript(model, feature_importance, accuracy):
    """
    Export model for JavaScript integration
    """
    print("\n" + "="*60)
    print("EXPORTING MODEL")
    print("="*60)
    
    # Save model
    with open('random_forest_model_optimized.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("✓ Model saved to: random_forest_model_optimized.pkl")
    
    # Get weights (feature importance)
    if feature_importance is not None:
        # Sort by original feature order for JavaScript
        weights = feature_importance.set_index('feature').loc[
            feature_importance['feature'][:16]  # First 16 original features
        ]['importance'].values
        
        weights_js = ', '.join([f"{w:.8e}" for w in weights])
        print(f"\n✓ JavaScript weights (top 16 features):")
        print(f"[{weights_js}]")
        
        # Export metadata
        export_data = {
            'model_type': 'RandomForest_Optimized',
            'accuracy': float(accuracy),
            'feature_importance': feature_importance.to_dict('records'),
            'weights_for_js': weights.tolist(),
            'training_date': '2025-12-15',
            'samples_trained': 1500
        }
        
        with open('model_export_optimized.json', 'w') as f:
            json.dump(export_data, f, indent=2)
        print("✓ Metadata saved to: model_export_optimized.json")

if __name__ == "__main__":
    print("="*60)
    print("ADVANCED TRAINING - TARGET: 80%+ ACCURACY")
    print("="*60)
    
    # Step 1: Load and enhance dataset
    X, y, feature_names = load_and_enhance_dataset()
    
    # Step 2: Handle class imbalance
    X, y = handle_class_imbalance(X, y)
    
    # Step 3: Train model
    print("\n" + "="*60)
    print("SELECT TRAINING MODE")
    print("="*60)
    print("1. Fast (Balanced Random Forest) - Recommended")
    print("2. Hyperparameter Optimization - Slower, potentially better")
    print("3. Ensemble (RF + Gradient Boosting) - Best accuracy, slowest")
    print("\nUsing Mode 1 (Fast) for initial run...")
    
    # Train with mode 1 (fast, balanced)
    model, accuracy, feature_importance = train_advanced_model(
        X, y, feature_names, 
        use_optimization=False, 
        use_ensemble=False
    )
    
    # If accuracy < 80%, try ensemble
    if accuracy < 0.80:
        print("\n" + "="*60)
        print(f"⚠ Accuracy {accuracy:.2%} < 80%, trying ensemble method...")
        print("="*60)
        model, accuracy, feature_importance = train_advanced_model(
            X, y, feature_names,
            use_optimization=False,
            use_ensemble=True
        )
    
    # Export
    export_for_javascript(model, feature_importance, accuracy)
    
    # Final summary
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"Final Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    if accuracy >= 0.80:
        print("✅ SUCCESS: Achieved 80%+ accuracy!")
    else:
        print(f"⚠ Current: {accuracy:.2%}. Need {0.80-accuracy:.2%} more for 80% target.")
        print("\nTo improve further:")
        print("1. Collect more diverse training data (especially malicious samples)")
        print("2. Add real-time features (SSL cert, domain age, external APIs)")
        print("3. Use deep learning (requires more data)")
        print("4. Implement active learning to continuously improve")
    
    print("\nNext step: Update content.js with new weights from model_export_optimized.json")
