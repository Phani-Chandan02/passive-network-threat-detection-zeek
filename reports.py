# reports.py
import pandas as pd

def save_reports(df):
    """
    Save anomaly results to CSV and a human-readable report.
    Also prints summary statistics.
    """
    if df.empty:
        print("⚠️ No data to report.")
        return

    # Save CSV
    df.to_csv("anomalies.csv", index=False)
    print("✅ anomalies.csv written.")

    # Aggregate per source IP
    agg = df.groupby("id.orig_h").agg(
        anomaly_count=("anomaly", "sum"),
        total_queries=("anomaly", "count"),
        avg_score=("anomaly_score", "mean")
    ).reset_index().rename(columns={"id.orig_h": "src_ip"})

    # Summary stats
    total_ips = len(agg)
    total_queries = agg["total_queries"].sum()
    total_anomalies = agg["anomaly_count"].sum()
    anomaly_pct = (total_anomalies / total_queries) * 100 if total_queries > 0 else 0

    top_domains = df["query"].value_counts().head(5).to_dict()

    print(f"📊 Total unique IPs: {total_ips}")
    print(f"📊 Total queries analyzed: {total_queries}")
    print(f"📊 Total anomalies: {total_anomalies} ({anomaly_pct:.2f}%)")
    print(f"📊 Top 5 domains: {top_domains}")

    # Write human-readable report
    with open("anomalies_report.txt", "w") as f:
        f.write("=== DNS Anomaly Report ===\n\n")
        f.write(f"Total unique IPs: {total_ips}\n")
        f.write(f"Total queries: {total_queries}\n")
        f.write(f"Total anomalies: {total_anomalies} ({anomaly_pct:.2f}%)\n\n")
        f.write("Top 5 domains:\n")
        for domain, count in top_domains.items():
            f.write(f"{domain}: {count}\n")
        f.write("\nDetailed per-IP summary:\n")
        f.write(agg.to_string(index=False))

    print("✅ anomalies_report.txt written.")
