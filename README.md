# 🚀 Network Traffic Analyzer Dashboard

## 📌 Overview
Analyze network traffic captured using Wireshark and get insights on:
- Top communicating IP
- Protocol usage (TCP/UDP)
- DNS activity
- Suspicious traffic patterns

## 🔥 Features
- Upload multiple `.pcap/.pcapng` files
- Protocol distribution charts
- Top IP detection
- DNS query counting
- Basic anomaly detection
- Downloadable reports
- Interactive dashboard (Streamlit)

## 🛠 Tech Stack
- Python
- Wireshark / PyShark
- Streamlit
- Pandas, Matplotlib

## ▶️ Run Locally
```bash
pip install -r requirements.txt
streamlit run app.py
