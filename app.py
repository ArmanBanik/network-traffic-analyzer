import streamlit as st
from collections import Counter
import tempfile
import pandas as pd
import matplotlib.pyplot as plt

# Safe import for cloud deployment
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except:
    PYSHARK_AVAILABLE = False

# Page config
st.set_page_config(page_title="Elite Network Analyzer", layout="wide")

# Title
st.title("🚀 Elite Network Traffic Analyzer")
st.markdown("Advanced packet analysis & anomaly detection dashboard")

# Warning for cloud
if not PYSHARK_AVAILABLE:
    st.warning("⚠️ Packet analysis is disabled in cloud deployment. Run locally for full functionality.")

# Sidebar
st.sidebar.header("⚙️ Controls")
uploaded_files = st.sidebar.file_uploader(
    "Upload .pcap/.pcapng files",
    type=["pcap", "pcapng"],
    accept_multiple_files=True
)

threshold = st.sidebar.slider("Suspicious Threshold", 100, 1000, 200)

# Helper function
def is_local(ip):
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")

# Analysis function
def analyze_file(file):
    if not PYSHARK_AVAILABLE:
        return None

    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(file.read())
    temp_file.close()

    capture = pyshark.FileCapture(temp_file.name)

    protocols = []
    ips = []
    dns_count = 0

    for packet in capture:
        try:
            if packet.transport_layer:
                protocols.append(packet.transport_layer)
            if hasattr(packet, 'ip'):
                ips.append(packet.ip.src)
            if 'DNS' in packet:
                dns_count += 1
        except:
            continue

    protocol_counter = Counter(protocols)
    ip_counter = Counter(ips)

    top_protocol = protocol_counter.most_common(1)[0][0] if protocol_counter else "N/A"
    top_ip = ip_counter.most_common(1)[0][0] if ip_counter else "N/A"

    suspicious = "NO"
    for ip, count in ip_counter.items():
        if not is_local(ip) and count > threshold:
            suspicious = "YES"

    if dns_count > 300:
        suspicious = "YES"

    return {
        "top_ip": top_ip,
        "protocol": top_protocol,
        "dns": dns_count,
        "suspicious": suspicious,
        "protocols": protocol_counter,
        "ips": ip_counter
    }

# Main app
if uploaded_files:

    if not PYSHARK_AVAILABLE:
        st.error("❌ Packet analysis not supported in this environment.")
        st.stop()

    results = []

    for file in uploaded_files:
        result = analyze_file(file)
        if result:
            results.append((file.name, result))

    # Comparison view
    st.markdown("## ⚔️ File Comparison")

    cols = st.columns(len(results))

    for i, (name, res) in enumerate(results):
        with cols[i]:
            st.subheader(name)
            st.metric("Top IP", res["top_ip"])
            st.metric("Protocol", res["protocol"])
            st.metric("DNS", res["dns"])
            st.metric("Suspicious", res["suspicious"])

    # Detailed view
    for name, res in results:
        st.markdown("---")
        st.header(f"📁 Detailed Analysis: {name}")

        col1, col2 = st.columns(2)

        proto_df = pd.DataFrame(res["protocols"].items(), columns=["Protocol", "Count"])
        ip_df = pd.DataFrame(res["ips"].most_common(5), columns=["IP", "Count"])

        if not proto_df.empty:
            col1.subheader("Protocol Distribution")
            col1.bar_chart(proto_df.set_index("Protocol"))

        if not ip_df.empty:
            col2.subheader("Top Active IPs")
            col2.bar_chart(ip_df.set_index("IP"))

        # Pie chart
        st.subheader("Protocol Share")
        if not proto_df.empty:
            fig, ax = plt.subplots()
            ax.pie(proto_df["Count"], labels=proto_df["Protocol"], autopct='%1.1f%%')
            st.pyplot(fig)

        # Download report
        report = f"""
File: {name}
Top IP: {res['top_ip']}
Protocol: {res['protocol']}
DNS Queries: {res['dns']}
Suspicious: {res['suspicious']}
"""
        st.download_button(
            label="📄 Download Report",
            data=report,
            file_name=f"{name}_report.txt"
        )

else:
    st.info("👈 Upload files from sidebar to start analysis")
