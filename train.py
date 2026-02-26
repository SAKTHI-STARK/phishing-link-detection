import pandas as pd
import pickle
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn import metrics
import os

def retrain_model():
    print("--- Retraining Model with Required Features ---")
    
    # 1. Load Data
    data_path = "phishing.csv"
    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found.")
        return
    
    df = pd.read_csv(data_path)
    
    # 2. Define Features to drop
    # 'Index' is always dropped.
    # 'WebsiteTraffic' is dropped because the Alexa API is retired.
    # You can add other unreliable features here (e.g., 'GoogleIndex', 'PageRank')
    features_to_drop = ['Index', 'WebsiteTraffic'] 
    
    print(f"Dropping unreliable features: {features_to_drop}")
    X = df.drop(features_to_drop + ['class'], axis=1)
    y = df['class']
    
    # Save the list of features used for the app to reference
    features_used = X.columns.tolist()
    print(f"Using {len(features_used)} features for training.")
    
    # 3. Split Data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 4. Train Model
    print("Training GradientBoostingClassifier...")
    gbc = GradientBoostingClassifier(max_depth=4, learning_rate=0.7)
    gbc.fit(X_train, y_train)
    
    # 5. Evaluate
    y_pred = gbc.predict(X_test)
    acc = metrics.accuracy_score(y_test, y_pred)
    print(f"Model trained. Test Accuracy: {acc*100:.2f}%")
    
    # 6. Save Model and Metadata
    os.makedirs("pickle", exist_ok=True)
    model_file = "pickle/model.pkl"
    with open(model_file, "wb") as f:
        pickle.dump(gbc, f)
    
    # Save the feature names so the app knows which ones to extract
    meta_file = "pickle/features_metadata.pkl"
    with open(meta_file, "wb") as f:
        pickle.dump(features_used, f)
        
    print(f"SUCCESS: New model saved to {model_file}")
    print(f"SUCCESS: Feature metadata saved to {meta_file}")

if __name__ == "__main__":
    retrain_model()
