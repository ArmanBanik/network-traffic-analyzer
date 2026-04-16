import streamlit as st
import pyshark
from collections import Counter
import tempfile
import pandas as pd
import matplotlib.pyplot as plt

# Page config
st.set_page_config(page_title=" Network Analyzer", layout="wide")

# Title
st.title("🚀  Network Traffic Analyzer")
st.markdown("Advanced analysis of network traffic with insights & anomaly detection")

# Sidebar
st.sidebar.header("⚙️ Controls")

uploaded_files = st.sidebar.file_uploader(
    "Upload Capture Files",
    type=["pcap", "pcapng"],
    accept_multiple_files=True
)

threshold = st.sidebar.slider("Suspicious Traffic Threshold", 100, 1000, 200)

# Helper
def is_local(ip):
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")

# Store reports for comparison
reports = []

# Main logic
if uploaded_files:

    for uploaded_file in uploaded_files:

        st.markdown("---")
        st.header(f"📁 {uploaded_file.name}")

        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(uploaded_file.read())
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

        # Status Indicator
        status_color = "🟢 Normal" if suspicious == "NO" else "🔴 Suspicious"

        # Metrics
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Top IP", top_ip)
        col2.metric("Protocol", top_protocol)
        col3.metric("DNS Queries", dns_count)
        col4.metric("Status", status_color)

        # Charts
        st.subheader("📊 Traffic Analysis")

        colA, colB = st.columns(2)

        proto_df = pd.DataFrame(protocol_counter.items(), columns=["Protocol", "Count"])
        ip_df = pd.DataFrame(ip_counter.most_common(5), columns=["IP", "Count"])

        if not proto_df.empty:
            colA.bar_chart(proto_df.set_index("Protocol"))

        if not ip_df.empty:
            colB.bar_chart(ip_df.set_index("IP"))

        # Pie Chart
        if not proto_df.empty:
            fig, ax = plt.subplots()
            ax.pie(proto_df["Count"], labels=proto_df["Protocol"], autopct='%1.1f%%')
            st.pyplot(fig)

        # Top Talkers Table
        st.subheader("🌐 Top Talkers")
        st.dataframe(ip_df)

        # Save report
        report = {
            "File": uploaded_file.name,
            "Top IP": top_ip,
            "Protocol": top_protocol,
            "DNS": dns_count,
            "Suspicious": suspicious
        }
        reports.append(report)

        # Download Report
        report_text = f"""
        File: {uploaded_file.name}
        Top IP: {top_ip}
        Protocol: {top_protocol}
        DNS Queries: {dns_count}
        Suspicious: {suspicious}
        """

        st.download_button(
            label="📄 Download Report",
            data=report_text,
            file_name=f"{uploaded_file.name}_report.txt"
        )

    # Comparison Section
    if len(reports) > 1:
        st.markdown("---")
        st.header("⚔️ Comparison View")

        df = pd.DataFrame(reports)
        st.dataframe(df)

else:
    st.info("👈 Upload capture files from the sidebar to start analysis")
