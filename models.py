# models.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump, load
import os

# ------------------------------------------------------
# 1️⃣ Train and Save Model
# ------------------------------------------------------
def train_model(X, contamination=0.02, n_estimators=200, random_state=42):
    """
    Train a new IsolationForest model on given features and save it.
    """
    clf = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    clf.fit(X)
    dump(clf, "dns_iforest.pkl")
    print("✅ Model trained and saved as dns_iforest.pkl")
    return clf

# ------------------------------------------------------
# 2️⃣ Load Existing Model
# ------------------------------------------------------
def load_model(model_path="dns_iforest.pkl", X=None, contamination=0.02):
    """
    Load saved IsolationForest model. If missing, train a new one.
    """
    if os.path.exists(model_path):
        clf = load(model_path)
        print(f"📦 Loaded model: {model_path}")
    else:
        if X is None:
            raise ValueError("❌ Model not found and no data provided to train a new one.")
        clf = train_model(X, contamination=contamination)
    return clf

# ------------------------------------------------------
# 3️⃣ Predict Anomalies
# ------------------------------------------------------
def predict_anomalies(model, X, original_df=None):
    """
    Run predictions and return dataframe with anomaly flags and scores.
    Optionally attach original DNS log info.
    """
    preds = model.predict(X)
    scores = -model.decision_function(X)

    result = pd.DataFrame({
        "anomaly": (preds == -1),
        "anomaly_score": scores
    })

    if original_df is not None:
        result = pd.concat([original_df.reset_index(drop=True), result], axis=1)

    return result
