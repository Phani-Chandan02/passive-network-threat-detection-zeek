# 🚨 Passive Network Threat Detection & SOC Analytics using Zeek

## 🔍 Overview

This project presents a **real-time Security Operations Center (SOC) analytics system** built on top of Zeek network logs. It combines **machine learning–based anomaly detection** with **multi-log correlation** to identify suspicious network behavior in both offline (PCAP) and live monitoring scenarios.

The system is designed to simulate a **lightweight SOC pipeline**, capable of detecting threats such as DNS anomalies, suspicious traffic patterns, and correlated multi-log events — all visualized through an interactive dashboard.

---

## ⚡ Key Features

* 🧠 **DNS Anomaly Detection**
  Uses Isolation Forest to detect abnormal DNS query patterns.

* 🔗 **Multi-Log Fusion Engine**
  Correlates logs (conn, dns, ntp, etc.) for higher-confidence alerts.

* 📡 **Real-Time Monitoring**
  Watches Zeek logs continuously and updates alerts dynamically.

* 📊 **SOC Dashboard (Streamlit)**
  Visual interface for monitoring anomalies and alerts.

* 📁 **Offline PCAP Analysis**
  Generate logs from PCAP files and run full pipeline.

* ⚙️ **Modular Pipeline**
  Clean separation of feature engineering, detection, and reporting.

---

## 🏗️ System Architecture

```
PCAP / Live Traffic
        │
        ▼
     Zeek Logs
(conn.log, dns.log, ntp.log)
        │
        ▼
 Feature Engineering
        │
        ▼
 ML Detection (Isolation Forest)
        │
        ▼
 Multi-Log Fusion Engine
        │
        ▼
 Alerts + Reports
        │
        ▼
 SOC Dashboard (Streamlit)
```

---

## 📂 Project Structure

```
zeek-soc/
│
├── scripts/
│   ├── dns_anomaly.py
│   ├── fusion_detection.py
│   ├── feature_agg.py
│   ├── live_watcher.py
│   ├── zeek_utils.py
│   ├── multi_log_utils.py
│   └── reports.py
│
├── app/
│   ├── app.py
│   └── soc_app.py
│
├── sample_data/
│   └── sample.pcap
│
├── requirements.txt
├── run.sh
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```
git clone https://github.com/your-username/zeek-soc.git
cd zeek-soc
```

---

### 2️⃣ Run Complete Pipeline

```
bash run.sh
```

---

## 🧪 Manual Execution (Step-by-Step)

### 🔹 Create Environment

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 🔹 Generate Zeek Logs from PCAP

```
mkdir -p logs
/opt/zeek/bin/zeek -C -r sample.pcap LogAscii::use_json=T
```

---

### 🔹 Run DNS Anomaly Detection

```
python dns_anomaly.py --contamination 0.02
```

---

### 🔹 Launch Dashboard

```
streamlit run app.py
```

---

### 🔹 Real-Time Monitoring

```
python live_watcher.py
streamlit run soc_app.py
```

---

## 📊 Outputs

* 📄 `anomalies.csv` → Detected DNS anomalies
* 📄 `fusion_alerts.csv` → Correlated alerts
* 📄 `anomalies_report.txt` → Human-readable report
* 📊 **Streamlit Dashboard** → Live SOC visualization

---

## 🧠 Detection Approach

### 1. Feature Engineering

* DNS query frequency
* Domain length
* Entropy of queries
* Request patterns

### 2. ML Model

* Isolation Forest (unsupervised anomaly detection)

### 3. Fusion Engine

* Combines multiple logs for context-aware detection
* Reduces false positives

---

## 🚀 Use Cases

* SOC simulation & training
* Network anomaly detection research
* Intrusion detection prototyping
* Cybersecurity academic projects

---

## ⚠️ Requirements

* Python 3.8+
* Zeek installed (`/opt/zeek/bin/zeek`)
* Streamlit

---

## 📌 Future Improvements

* Deep learning-based anomaly detection
* Real-time packet capture integration
* Threat intelligence enrichment
* Alert severity scoring

---

## 👨‍💻 Authors

**Phani Chandan Reddy**
**Sai Vivek Reddy**

---

## ⭐ Acknowledgment

This project is inspired by real-world SOC workflows and modern network security monitoring systems.

---

## 📬 Contact

For queries or collaboration:
📧 Reach out via GitHub Issues or Discussions

---

## ⭐ If you like this project

Give it a ⭐ on GitHub — it helps a !
