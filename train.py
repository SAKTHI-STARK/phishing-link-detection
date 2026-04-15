import pandas as pd
import pickle
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn import metrics
import os

def retrain_model():
    print("--- Retraining Model with XGBoost ---")
    
    # 1. Load Data
    data_path = "phishing_augmented_balanced.csv"
    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found.")
        return
    
    df = pd.read_csv(data_path)
    
    # 2. Define Features to drop
    # 'Index' is always dropped.
    # 'GoogleIndex' is dropped because the Google Search API is unreliable/rate-limited.
    features_to_drop = ['Index', 'GoogleIndex'] 
    
    # Only drop columns that exist in the dataset
    features_to_drop = [f for f in features_to_drop if f in df.columns]
    
    print(f"Dropping features: {features_to_drop}")
    X = df.drop(features_to_drop + ['class'], axis=1)
    y = df['class']
    
    # XGBoost expects labels in [0, 1] for binary classification.
    # Dataset uses -1 for phishing and 1 for legitimate.
    # Mapping: -1 -> 0 (Phishing), 1 -> 1 (Legitimate)
    y = y.map({-1: 0, 1: 1})
    
    # Save the list of features used for the app to reference
    features_used = X.columns.tolist()
    print(f"Using {len(features_used)} features for training:")
    for i, f in enumerate(features_used, 1):
        print(f"  {i:2d}. {f}")
    
    # 3. Split Data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, shuffle=True, stratify=y)
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Testing set:  {len(X_test)} samples")

    # 4. Train Model
    print("\nTraining XGBClassifier...")
    xgb = XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.03,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1,
        random_state=42,
        eval_metric='logloss'
    )
    xgb.fit(X_train, y_train)
    
    # 5. Evaluate
    y_pred = xgb.predict(X_test)
    acc = metrics.accuracy_score(y_test, y_pred)
    print(f"\n{'='*50}")
    print(f"Test Accuracy: {acc*100:.2f}%")
    print(f"{'='*50}")
    print("\nClassification Report:")
    print(metrics.classification_report(y_test, y_pred, target_names=["Phishing (0)", "Legitimate (1)"]))
    
    # Confusion Matrix
    cm = metrics.confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"  True Phishing  (TP): {cm[0][0]}")
    print(f"  False Legit    (FN): {cm[0][1]}  << missed phishing (want this LOW)")
    print(f"  False Phishing (FP): {cm[1][0]}  << false alarms (want this LOW)")
    print(f"  True Legit     (TN): {cm[1][1]}")
    
    # 6. Save Model and Metadata
    os.makedirs("pickle", exist_ok=True)
    model_file = "pickle/model.pkl"
    with open(model_file, "wb") as f:
        pickle.dump(xgb, f)
    
    # Save the feature names so the app knows which ones to extract
    meta_file = "pickle/features_metadata.pkl"
    with open(meta_file, "wb") as f:
        pickle.dump(features_used, f)
        
    print(f"\nSUCCESS: New model saved to {model_file}")
    # just to make sure the feature passed to model in same order as trained
    print(f"SUCCESS: Feature metadata saved to {meta_file}")

if __name__ == "__main__":
    retrain_model()
