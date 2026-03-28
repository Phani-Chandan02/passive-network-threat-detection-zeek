# live_watcher.py
import time, os, threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from multi_log_utils import load_dns, load_http, load_ssl, load_conn
from feature_agg import dns_features_per_query, http_features_per_request, ssl_features_per_conn, conn_features_per_conn, aggregate_window
from fusion_detector import build_feature_matrix, load_or_train, score_ensemble, correlation_rules, train_iforest

class ZeekLogHandler(FileSystemEventHandler):
    def __init__(self, log_dir="logs", window_seconds=300):
        self.log_dir = log_dir
        self.window_seconds = window_seconds
        # model lazy loaded
        self.model = None

    def on_modified(self, event):
        # when any log changes, re-run detection
        try:
            self.run_cycle()
        except Exception as e:
            print("Error in run_cycle:", e)

    def run_cycle(self):
        now = pd.Timestamp.utcnow()
        dns = load_dns(log_dir=self.log_dir)
        http = None
        ssl = None
        conn = None
        try:
            http = load_http(log_dir=self.log_dir)
        except FileNotFoundError:
            pass
        try:
            ssl = load_ssl(log_dir=self.log_dir)
        except FileNotFoundError:
            pass
        try:
            conn = load_conn(log_dir=self.log_dir)
        except FileNotFoundError:
            pass

        dns_e = dns_features_per_query(dns)
        http_e = http_features_per_request(http) if http is not None else None
        ssl_e = ssl_features_per_conn(ssl) if ssl is not None else None
        conn_e = conn_features_per_conn(conn) if conn is not None else None

        dns_agg = aggregate_window(dns_e, ts_col='ts', group_col='id.orig_h', window_seconds=self.window_seconds)
        http_agg = aggregate_window(http_e, ts_col='ts', group_col='id.orig_h', window_seconds=self.window_seconds) if http_e is not None else None
        ssl_agg = aggregate_window(ssl_e, ts_col='ts', group_col='id.orig_h', window_seconds=self.window_seconds) if ssl_e is not None else None
        conn_agg = aggregate_window(conn_e, ts_col='ts', group_col='src_ip', window_seconds=self.window_seconds) if conn_e is not None else None

        merged, X = build_feature_matrix(dns_agg, http_agg, ssl_agg, conn_agg)

        if X.empty or X.shape[1] == 0:
            print("⚠ No numeric features available yet — skipping cycle")
            return

        if self.model is None:
            try:
                if self.model is None:
                    if len(X) < 5:
                        print("⚠ Not enough data to train model yet")
                        return
                    self.model = load_or_train(X, path="fusion_iforest.pkl", contamination=0.02)

            except Exception:
                self.model = train_iforest(X, contamination=0.02, save_path="fusion_iforest.pkl")

        preds, scores = score_ensemble(self.model, X)
        merged['anomaly'] = (preds == -1)
        merged['anomaly_score'] = scores

        alerts = correlation_rules(dns, http, ssl, conn, merged)

        # persist outputs for dashboard
        merged.to_csv("fusion_anomalies.csv", index=False)
        alerts.to_csv("fusion_alerts.csv", index=False)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Cycle done: {len(merged)} hosts, {len(alerts)} alerts")

if __name__ == '__main__':
    import pandas as pd
    log_dir = "logs"
    handler = ZeekLogHandler(log_dir=log_dir, window_seconds=300)
    observer = Observer()
    observer.schedule(handler, path=log_dir, recursive=False)
    observer.start()
    print("Started Zeek live watcher on", log_dir)

# 🔥 FORCE FIRST RUN (CRITICAL)
    print("⚡ Running initial detection cycle")
    handler.run_cycle()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()
    observer.join()
