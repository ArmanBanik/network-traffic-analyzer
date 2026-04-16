import pyshark
from collections import Counter

# Load capture file
capture = pyshark.FileCapture('capture.pcapng')

protocols = []
ips = []
dns_count = 0

# Function to check local IPs
def is_local(ip):
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")

# Read packets
for packet in capture:
    try:
        # Protocol detection
        if packet.transport_layer:
            protocols.append(packet.transport_layer)

        # IP detection
        if hasattr(packet, 'ip'):
            ips.append(packet.ip.src)

        # DNS detection
        if 'DNS' in packet:
            dns_count += 1

    except:
        continue

# Count protocols and IPs
protocol_counter = Counter(protocols)
ip_counter = Counter(ips)

# Get top values
top_protocol = protocol_counter.most_common(1)[0][0] if protocol_counter else "N/A"
top_ip = ip_counter.most_common(1)[0][0] if ip_counter else "N/A"

# Smart suspicious detection
suspicious = "NO"

# Detect high traffic from external IPs
for ip, count in ip_counter.items():
    if not is_local(ip) and count > 200:
        suspicious = "YES"

# Detect DNS flood
if dns_count > 300:
    suspicious = "YES"

# Print report
print("\n=== Network Traffic Report ===\n")

print(f"Top IP: {top_ip}")
print(f"Most used protocol: {top_protocol}")
print(f"DNS queries detected: {dns_count}")
print(f"Suspicious activity: {suspicious}")
