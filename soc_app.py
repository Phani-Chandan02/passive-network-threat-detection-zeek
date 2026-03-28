# soc_app.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import ipaddress
import geoip2.database
import os

st.set_page_config(page_title="Zeek SOC Dashboard", layout="wide")
st.title("🔒 Zeek SOC Dashboard — Fusion Mode")

# Load fusion outputs
try:
    df = pd.read_csv("fusion_anomalies.csv")
except Exception as e:
    st.error("fusion_anomalies.csv missing — run live_watcher.py or fusion pipeline")
    st.stop()

alerts = pd.DataFrame()
try:
    alerts = pd.read_csv("fusion_alerts.csv")
except Exception:
    alerts = pd.DataFrame(columns=['src_ip','alert','score'])

# Top KPIs
col1, col2, col3, col4 = st.columns(4)
col1.metric("Hosts Monitored", int(df['src_ip'].nunique()))
col2.metric("Current Alerts", len(alerts))
col3.metric("Anomalous Hosts", int(df['anomaly'].sum()))
col4.metric("Avg Anomaly Score", round(float(df['anomaly_score'].mean()),4))

st.markdown("---")
# Alerts panel
st.subheader("⚠ Alerts")
if not alerts.empty:
    st.dataframe(alerts.sort_values('score', ascending=False).reset_index(drop=True))
else:
    st.write("No alerts currently")

# Timeline (anomalies over time) — requires original raw logs with timestamps; we approximate by reloading DNS logs for timeline
from multi_log_utils import load_dns, load_http, load_conn, load_ssl
dns_raw = load_dns()
dns_raw['ts_local'] = pd.to_datetime(dns_raw['ts'])
# aggregate anomalies by minute
timeline = dns_raw.set_index('ts_local').resample('1Min').size().reset_index(name='events')
fig = px.area(timeline, x='ts_local', y='events', title="Events per Minute")
st.plotly_chart(fig, use_container_width=True)

# Sankey: src_ip -> domain (top N)
st.subheader("Sankey: Host → Domain (Top flows)")
if 'query' in dns_raw.columns:
    top = dns_raw.groupby(['id.orig_h','query']).size().reset_index(name='count')
    topn = top.sort_values('count', ascending=False).head(200)
    srcs = topn['id.orig_h'].astype(str).unique().tolist()
    dsts = topn['query'].astype(str).unique().tolist()
    nodes = srcs + dsts
    node_index = {n:i for i,n in enumerate(nodes)}
    links = dict(
        source=[node_index[r['id.orig_h']] for _,r in topn.iterrows()],
        target=[node_index[r['query']] for _,r in topn.iterrows()],
        value=topn['count'].tolist()
    )
    sankey = go.Figure(data=[go.Sankey(node=dict(label=nodes), link=links)])
    st.plotly_chart(sankey, use_container_width=True)
else:
    st.write("No DNS raw data available for Sankey")

# GeoIP map (if mmdb available)
st.subheader("GeoIP Map (destination IPs)")
mmdb_path = os.getenv('GEOIP_DB', 'GeoLite2-City.mmdb')
if os.path.exists(mmdb_path):
    reader = geoip2.database.Reader(mmdb_path)
    conn_raw = load_conn()
    # find external dest IPs
    def ip_to_loc(ip):
        try:
            rr = reader.city(ip)
            return rr.location.latitude, rr.location.longitude, rr.country.iso_code
        except Exception:
            return None
    coords = []
    for ip in conn_raw['dest_ip'].dropna().unique():
        if ip.startswith(('10.','192.168.','172.16.')):
            continue
        loc = ip_to_loc(ip)
        if loc:
            coords.append({'ip':ip,'lat':loc[0],'lon':loc[1],'cc':loc[2]})
    if coords:
        coords_df = pd.DataFrame(coords)
        fig = px.scatter_geo(coords_df, lat='lat', lon='lon', hover_name='ip', color='cc', title="Destinations GeoIP")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.write("No external destinations resolved to GeoIP")
else:
    st.info("GeoIP DB not found. Set GEOIP_DB env to path of GeoLite2-City.mmdb to enable maps.")

# Drilldown: pick a host
st.markdown("---")
st.subheader("🔎 Drilldown Investigator")
host = st.selectbox("Select host", df['src_ip'].unique())
if host:
    st.write("Anomaly row:")
    st.dataframe(df[df['src_ip']==host].T)

    # show raw DNS
    dr = dns_raw[dns_raw['id.orig_h']==host].sort_values('ts').tail(200)
    st.write("Recent DNS queries:")
    st.dataframe(dr[['ts','query','qtype_name','rcode_name']].tail(200))

    # show HTTP and conn if available
    try:
        http_raw = load_http()
        st.write("Recent HTTP requests:")
        st.dataframe(http_raw[http_raw['id.orig_h']==host][['ts','method','host','uri','user_agent']].tail(200))
    except Exception:
        st.write("No HTTP data")

    try:
        conn_raw = load_conn()
        st.write("Recent connections from host:")
        st.dataframe(conn_raw[conn_raw['src_ip']==host][['ts','dest_ip','dest_port','proto','duration']].tail(200))
    except Exception:
        st.write("No conn data")
