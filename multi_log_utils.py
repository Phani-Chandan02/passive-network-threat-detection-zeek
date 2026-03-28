# multi_log_utils.py
import glob, os, json
import pandas as pd
from datetime import datetime

def find_latest_log(log_dir="logs", pattern="*.log"):
    paths = glob.glob(os.path.join(log_dir, pattern))
    if not paths:
        raise FileNotFoundError(f"No logs matching {pattern} in {log_dir}")
    return max(paths, key=os.path.getmtime)

def load_jsonlines(path):
    # robust loading for Zeek JSON line files
    rows = []
    with open(path, "r", errors="ignore") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except Exception:
                # skip malformed lines
                continue
    return pd.DataFrame(rows)

def load_dns(path=None, log_dir="logs"):
    if path is None:
        path = find_latest_log(log_dir, "dns*.log")
    df = load_jsonlines(path)
    df['ts'] = pd.to_datetime(df['ts'], unit='s', utc=True)
    # normalize expected fields
    if 'query' not in df.columns:
        # try other names
        for c in ['qname','query_name']:
            if c in df.columns:
                df['query'] = df[c].astype(str)
                break
    return df

def load_http(path=None, log_dir="logs"):
    if path is None:
        path = find_latest_log(log_dir, "http*.log")
    df = load_jsonlines(path)
    df['ts'] = pd.to_datetime(df['ts'], unit='s', utc=True)
    # normalize
    df['method'] = df.get('method', df.get('request_method', None))
    df['host'] = df.get('host', None)
    df['uri'] = df.get('uri', df.get('request_uri', None))
    df['user_agent'] = df.get('user_agent', df.get('header_user_agent', None))
    return df

def load_ssl(path=None, log_dir="logs"):
    if path is None:
        path = find_latest_log(log_dir, "ssl*.log")
    df = load_jsonlines(path)
    df['ts'] = pd.to_datetime(df['ts'], unit='s', utc=True)
    # normalize fields: JA3/JA3S may not be present depending on Zeek config
    df['ja3'] = df.get('ja3', None)
    df['certificate_chain'] = df.get('cert_chain', df.get('x509', None))
    df['subject'] = df.get('x509_subject', None)
    return df

def load_conn(path=None, log_dir="logs"):
    if path is None:
        path = find_latest_log(log_dir, "conn*.log")
    df = load_jsonlines(path)
    df['ts'] = pd.to_datetime(df['ts'], unit='s', utc=True)
    # normalize
    df['src_ip'] = df.get('id.orig_h', df.get('src_ip', None))
    df['dest_ip'] = df.get('id.resp_h', df.get('dest_ip', None))
    df['src_port'] = df.get('id.orig_p', df.get('src_port', None))
    df['dest_port'] = df.get('id.resp_p', df.get('dest_port', None))
    df['proto'] = df.get('proto', None)
    df['duration'] = df.get('duration', 0.0)
    df['state'] = df.get('state', None)
    return df
