#!/bin/bash

echo "🚀 Setting up environment..."

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

echo "📂 Creating logs directory..."
mkdir -p logs

echo "📡 Running Zeek on sample PCAP..."
/opt/zeek/bin/zeek -C -r sample.pcap LogAscii::use_json=T

echo "🧠 Running DNS anomaly detection..."
python dns_anomaly.py --contamination 0.02

echo "🔥 Starting SOC dashboard..."
streamlit run app.py