# dns_anomaly.py
import argparse
import pandas as pd
from zeek_utils import load_latest_dns_log, extract_dns_features
from models import train_model, load_model, predict_anomalies
from reports import save_reports

def main():
    # ✅ Argument parser setup
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true", help="Train a new IsolationForest model")
    ap.add_argument("--contamination", type=float, default=0.02, help="Proportion of anomalies")
    args = ap.parse_args()

    print("🔍 Loading latest Zeek DNS log...")
    dns_df = load_latest_dns_log()

    print("⚙️ Extracting features...")
    X = extract_dns_features(dns_df)

    model_path = "dns_iforest.pkl"

    # ✅ Train or load model
    if args.train:
        print("🧠 Training IsolationForest model...")
        model = train_model(X, contamination=args.contamination)
    else:
        print("📦 Loading saved model (or training if missing)...")
        model = load_model(model_path, X, contamination=args.contamination)

    # ✅ Predict anomalies
    print("🚨 Scoring DNS queries for anomalies...")
    results_df = predict_anomalies(model, X, dns_df)

    # ✅ Save reports
    save_reports(results_df)

    print("✅ Analysis complete!")
    print("📊 Results saved to anomalies.csv and anomalies_report.txt")

if __name__ == "__main__":
    main()
