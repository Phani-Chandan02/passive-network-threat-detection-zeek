# fusion_detector.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump, load
import os, time

MODEL_PATH = "fusion_iforest.pkl"

def build_feature_matrix(dns_agg, http_agg=None, ssl_agg=None, conn_agg=None):
    frames = []

    def normalize(df):
        if df is None or df.empty:
            return None
        if 'src_ip' not in df.columns:
            # 🔥 FINAL SAFETY NET
            for c in ['id.orig_h', 'orig_h', 'source_ip']:
                if c in df.columns:
                    df = df.rename(columns={c: 'src_ip'})
                    break
        if 'src_ip' not in df.columns:
            return None
        return df.set_index('src_ip')

    for df in [dns_agg, http_agg, ssl_agg, conn_agg]:
        ndf = normalize(df)
        if ndf is not None:
            frames.append(ndf)

    if not frames:
        raise ValueError("No valid aggregated data with src_ip")

    merged = pd.concat(frames, axis=1).fillna(0)
    X = merged.select_dtypes(include=[np.number])

    return merged.reset_index(), X



def train_iforest(X, contamination=0.02, save_path=MODEL_PATH):
    clf = IsolationForest(n_estimators=300, contamination=contamination, random_state=42, n_jobs=-1)
    clf.fit(X)
    dump(clf, save_path)
    return clf

def load_or_train(X=None, path=MODEL_PATH, contamination=0.02):
    if os.path.exists(path):
        clf = load(path)
    else:
        if X is None:
            raise ValueError("No feature matrix to train on")
        clf = train_iforest(X, contamination, path)
    return clf

def score_ensemble(clf, X):
    preds = clf.predict(X)
    scores = -clf.decision_function(X)
    return preds, scores

# Simple rule engine for correlated alerts
def correlation_rules(dns_raw, http_raw, ssl_raw, conn_raw, merged_df):
    """
    Return a DataFrame of alerts per src_ip with reason codes.
    Rules:
      - DNS anomaly + large HTTP POST within window -> 'DNS+HTTP_EXFIL'
      - High NXDOMAIN ratio + high entropy -> 'DGA_SUSPECT'
      - Multiple dest ports within short time -> 'PORT_SCAN'
      - Self-signed certs + JA3 rare -> 'SUSPICIOUS_TLS'
    """
    alerts = []
    # Example: detect high POST sizes per IP from http_raw
    if http_raw is not None and not http_raw.empty:
        post_sum = http_raw.groupby('id.orig_h').agg(total_post_size=('body_len','sum'), post_count=('has_post','sum')).reset_index()
        for _, row in post_sum.iterrows():
            if row['total_post_size'] > 1e6:  # >1 MB in window
                alerts.append({'src_ip': row['id.orig_h'], 'alert': 'HTTP_LARGE_POST', 'score': row['total_post_size']})
    # Example: detect port scan from conn_raw
    if conn_raw is not None and not conn_raw.empty:
        ports = conn_raw.groupby('src_ip').agg(unique_ports=('dest_port', lambda s: s.nunique()), conn_count=('dest_port','count')).reset_index()
        for _, row in ports.iterrows():
            if row['unique_ports'] > 50 and row['conn_count'] > 60:
                alerts.append({'src_ip': row['src_ip'], 'alert': 'PORT_SCAN', 'score': row['unique_ports']})
    # TLS checks
    if ssl_raw is not None and not ssl_raw.empty:
        certs = ssl_raw.groupby('id.orig_h').agg(self_signed_count=('certificate_chain', lambda arr: sum(1 for c in (arr or []) if c and 'self-signed' in str(c).lower())), ja3_missing=('ja3', lambda s: s.isna().sum())).reset_index()
        for _, row in certs.iterrows():
            if row['self_signed_count'] > 0:
                alerts.append({'src_ip': row['id.orig_h'], 'alert': 'SELF_SIGNED_CERT', 'score': row['self_signed_count']})
    return pd.DataFrame(alerts)
