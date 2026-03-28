# zeek_utils.py
import os
import glob
import pandas as pd
import numpy as np
import json
from collections import Counter
from math import log2

# ------------------------------------------------------
# 1️⃣ Find and load the latest Zeek DNS log automatically
# ------------------------------------------------------

def load_latest_dns_log(log_dir="logs"):
    import glob, os
    latest = max(glob.glob(f"{log_dir}/dns*.log"), key=os.path.getmtime)
    print(f"📂 Using latest log file: {latest}")
    
    # Load JSON lines
    with open(latest, "r") as f:
        lines = f.readlines()
    data = [json.loads(line) for line in lines]
    df = pd.DataFrame(data)
    
    return df
# ------------------------------------------------------
# 2️⃣ Feature Extraction
# ------------------------------------------------------
def shannon_entropy(s):
    """Compute Shannon entropy of a string"""
    if len(s) == 0:
        return 0
    counts = np.array([s.count(c) for c in set(s)])
    probs = counts / counts.sum()
    return -np.sum(probs * np.log2(probs))

def extract_dns_features(df):
    features = pd.DataFrame()
    features["query_len"] = df["query"].astype(str).apply(len)
    features["entropy"] = df["query"].astype(str).apply(shannon_entropy)
    features["digit_ratio"] = df["query"].astype(str).apply(
        lambda x: sum(c.isdigit() for c in x)/len(x) if len(x) > 0 else 0
    )
    features["label_count"] = df["query"].astype(str).apply(lambda x: x.count('.') + 1)
    features["max_label_len"] = df["query"].astype(str).apply(
        lambda x: max((len(p) for p in x.split('.')), default=0)
    )

    # Optional categorical encoding
    for col in ["qtype_name", "rcode_name"]:
        if col in df.columns:
            features[col] = df[col].astype("category").cat.codes
        else:
            features[col] = 0

    features.fillna(0, inplace=True)
    return features

