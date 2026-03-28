#!/usr/bin/env python3
"""
app.py
Streamlit dashboard for Zeek DNS anomalies
"""
import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

st.set_page_config(page_title="Zeek DNS Anomaly Explorer", layout="wide")

st.title("🕵️ Zeek DNS Anomaly Explorer")
st.markdown("Analyze and visualize DNS anomalies detected by your ML model.")

# Load CSV safely
try:
    df = pd.read_csv('anomalies.csv')
except Exception as e:
    st.error("No anomalies.csv found. Run dns_anomaly.py first. Error: {}".format(e))
    st.stop()

# Use Zeek column names safely
src_col = 'id.orig_h' if 'id.orig_h' in df.columns else 'src_ip'
score_col = 'anomaly_score'
flag_col = 'anomaly'

# Sidebar Filters
st.sidebar.header("Filters & Options")
score_min, score_max = st.sidebar.slider(
    "Anomaly score range",
    float(df[score_col].min()),
    float(df[score_col].max()),
    (float(df[score_col].min()), float(df[score_col].max()))
)
show_only_anom = st.sidebar.checkbox("Show only flagged anomalies", value=True)

filtered = df[(df[score_col] >= score_min) & (df[score_col] <= score_max)]
if show_only_anom:
    filtered = filtered[filtered[flag_col] == True]

# Download button
st.sidebar.markdown("---")
st.sidebar.download_button(
    label="Download filtered CSV",
    data=filtered.to_csv(index=False),
    file_name="anomalies_filtered.csv"
)

# Summary Metrics
st.subheader("📊 Summary Metrics")
col1, col2, col3 = st.columns(3)
col1.metric("Total Unique IPs", df[src_col].nunique())
col2.metric("Flagged Anomalies", int(df[flag_col].sum()))
col3.metric("Average Anomaly Score", round(float(df[score_col].mean()), 4))

# Top flagged IPs
st.subheader("🚩 Top Flagged IPs / Hosts")
st.dataframe(
    filtered.sort_values(score_col, ascending=False)
    .head(20)
    .reset_index(drop=True)
)

# Select IP/Host to inspect
st.subheader("🔎 Inspect Specific IP / Host")
ip = st.selectbox("Select IP/Host", options=filtered[src_col].unique())
if ip:
    st.dataframe(filtered[filtered[src_col] == ip].reset_index(drop=True))

# Charts
st.subheader("📈 Anomaly Score Distribution (Top 50)")
top_chart_df = df.sort_values(score_col, ascending=False).head(50).set_index(src_col)
st.bar_chart(top_chart_df[score_col])

# Heatmap of anomalies vs query types (if available)
if 'qtype_name' in df.columns:
    st.subheader("🔥 Heatmap: Anomalies vs Query Type")
    pivot = pd.pivot_table(filtered, values=score_col, index='qtype_name', columns=src_col, aggfunc='mean', fill_value=0)
    fig, ax = plt.subplots(figsize=(12, 6))
    sns.heatmap(pivot, cmap="Reds", linewidths=0.5, ax=ax)
    st.pyplot(fig)

# Top 10 most queried domains (if available)
if 'query' in df.columns:
    st.subheader("🌐 Top 10 Queried Domains")
    top_domains = df['query'].value_counts().head(10).reset_index()
    top_domains.columns = ['Domain', 'Count']
    st.table(top_domains)

st.caption(
    "ℹ️ Auto-refresh: Re-run dns_anomaly.py to update anomalies.csv. "
    "For live setups, schedule dns_anomaly.py periodically."
)
