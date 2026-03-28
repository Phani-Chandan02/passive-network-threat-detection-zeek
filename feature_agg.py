# feature_agg.py
import pandas as pd
import numpy as np
from collections import Counter
from math import log2
import time

def shannon_entropy(s: str) -> float:
    if not isinstance(s, str) or s == "":
        return 0.0
    counts = np.array([s.count(ch) for ch in set(s)])
    probs = counts / counts.sum()
    return -np.sum(probs * np.log2(probs))

def dns_features_per_query(dns_df: pd.DataFrame) -> pd.DataFrame:
    df = dns_df.copy()
    df['query'] = df['query'].astype(str)
    df['q_len'] = df['query'].str.len()
    df['label_count'] = df['query'].str.count(r'\.') + 1
    df['digits'] = df['query'].str.count(r'\d')
    df['digit_ratio'] = df['digits'] / df['q_len'].replace(0,1)
    df['max_label_len'] = df['query'].str.split('.').apply(lambda parts: max((len(p) for p in parts), default=0))
    df['entropy'] = df['query'].apply(shannon_entropy)
    return df

def http_features_per_request(http_df: pd.DataFrame) -> pd.DataFrame:
    df = http_df.copy()
    df['uri_len'] = df['uri'].fillna('').astype(str).str.len()
    df['has_post'] = (df['method'] == 'POST').astype(int)
    df['ua_len'] = df['user_agent'].fillna('').astype(str).str.len()
    # approximate body size if available
    df['body_len'] = df.get('resp_body_len', df.get('request_body_len', 0)).fillna(0).astype(float)
    return df

def ssl_features_per_conn(ssl_df: pd.DataFrame) -> pd.DataFrame:
    df = ssl_df.copy()
    df['cert_count'] = df['certificate_chain'].apply(lambda x: len(x) if isinstance(x,list) else 0)
    # cert age: we may have not before/after; placeholder zero
    df['ja3_missing'] = df['ja3'].isna().astype(int)
    return df

def conn_features_per_conn(conn_df: pd.DataFrame) -> pd.DataFrame:
    df = conn_df.copy()
    df['is_internal'] = df['src_ip'].astype(str).str.startswith(('10.','192.168.','172.16.'))
    df['is_long'] = (df['duration'].fillna(0) > 300).astype(int)  # >5min
    return df

print("DEBUG aggregate_window group_col =", group_col)
print("DEBUG df columns =", df.columns.tolist())

# Aggregations: group by src_ip and sliding time windows
def aggregate_window(df: pd.DataFrame, ts_col='ts', group_col='src_ip', window_seconds=300, now=None):
    """
    Aggregate features per src_ip over a sliding window.
    ALWAYS outputs a column named 'src_ip'.
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=['src_ip'])

    if now is None:
        now = pd.Timestamp.utcnow()

    cutoff = now - pd.Timedelta(seconds=window_seconds)
    dfw = df[df[ts_col] >= cutoff]

    if dfw.empty:
        return pd.DataFrame(columns=['src_ip'])

    agg = dfw.groupby(group_col).agg(
        event_count=(ts_col, 'count'),
        **{
            c: ('mean')
            for c in dfw.select_dtypes(include=['number']).columns
            if c != ts_col
        }
    ).reset_index()

    # 🔥 CRITICAL NORMALIZATION STEP
    agg = agg.rename(columns={group_col: 'src_ip'})
    print("DEBUG agg columns AFTER rename =", agg.columns.tolist())

    return agg

