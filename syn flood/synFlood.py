from ipaddress import ip_network, ip_address
from scapy.all import IP, TCP
from scapy.utils import rdpcap

# Define the attacked network range (IP addresses targeted by the SYN flood attack)
attacked_network = ip_network("100.64.0.0/16")

# Initialize a set to store suspicious IPs and a dictionary to count SYN requests per IP
suspicious_attackers = set()
syn_requests_per_ip = {}

# Load the PCAP file containing captured network traffic
pcapFile = rdpcap("SYNflood.pcapng")

# Analyze each packet in the PCAP file
for pkt in pcapFile:
    # Check if the packet has IP and TCP layers and is targeting the attacked network
    if pkt.haslayer(IP) and pkt.haslayer(TCP) \
            and ip_address(pkt[IP].src) not in attacked_network \
            and ip_address(pkt[IP].dst) in attacked_network:

        src_ip = pkt[IP].src  # Extract the source IP address

        # Check if the packet is a SYN request (potential sign of an attack)
        if pkt[TCP].flags == 'S':
            # Increment the SYN request count for this source IP
            syn_requests_per_ip[src_ip] = syn_requests_per_ip.get(src_ip, 0) + 1

        # Check if the packet is an ACK
        elif pkt[TCP].flags == 'A':
            # Decrease the SYN count if ACK indicates a legitimate response
            if src_ip in syn_requests_per_ip and syn_requests_per_ip[src_ip] > 0:
                syn_requests_per_ip[src_ip] -= 1

# Identify suspicious IPs with at least 10 unmatched SYN requests
for ip, syn_count in syn_requests_per_ip.items():
    if syn_count >= 10:
        suspicious_attackers.add(ip)

# Print the list of suspicious IP addresses
print("Suspicious attackers IP addresses:")
for ip in suspicious_attackers:
    print(ip)

# Print the total count of suspicious IP addresses
print(f"\nAmount of suspicious IP addresses: {len(suspicious_attackers)}")


# Verify if the detected attackers match the provided list of 51 known attackers
"""
with open("attackersListFiltered.txt", "r") as file:
    ip_set_from_file = set(line.strip() for line in file)

# Compare the detected attackers with the provided list and ensure all are detected
intersection = ip_set_from_file & suspicious_attackers
if len(intersection) == 51:
    print("\nContains all 51 IP addresses from file!")
"""
