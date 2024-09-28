from scapy.all import sniff, IP, TCP
import logging
import os
from datetime import datetime

#Logging configuration for all packets and threats
log_all_packets = "all_packets_log.txt"
log_potential_threats = "potential_threats_log.txt"
log_dangerous_threats = "dangerous_threats_log.txt"

#logging for all packets
logging.basicConfig(filename=log_all_packets, level=logging.INFO, format='%(asctime)s - %(message)s')

#logging for potential threats
potential_threat_logger = logging.getLogger('potential_threats')
potential_threat_logger.setLevel(logging.INFO)
potential_threat_handler = logging.FileHandler(log_potential_threats)
potential_threat_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
potential_threat_logger.addHandler(potential_threat_handler)

#logging for dangerous threats
dangerous_threat_logger = logging.getLogger('dangerous_threats')
dangerous_threat_logger.setLevel(logging.INFO)
dangerous_threat_handler = logging.FileHandler(log_dangerous_threats)
dangerous_threat_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
dangerous_threat_logger.addHandler(dangerous_threat_handler)

# Suspicious IPs and protocols
suspicious_ips = ["192.168.1.100", "10.0.0.5", "198.51.100.0/24"]
suspicious_protocols = ["FTP", "Telnet"]

# Traffic and port scan thresholds
traffic_threshold = 100
port_scan_threshold = 5
ip_ports = {}
traffic_count = {}

# Function to handle packet sniffing and logging
def packet_callback(packet):
    # Log all packets
    if packet.haslayer(IP):
        log_message = f"IP Packet: {packet[IP].src} -> {packet[IP].dst}"
    else:
        log_message = f"Non-IP Packet: {packet.summary()}"
    
    logging.info(log_message)  # Log all packets
    print(log_message)  # Print the packet to console for real-time feedback

    # Check for suspicious packets and log threats
    if is_suspicious(packet):
        threat_type = classify_threat(packet)
        log_threat(threat_type, log_message)

# Function to classify the threat as 'potential' or 'dangerous'
def classify_threat(packet):
    # Classify based on criteria (this logic can be expanded)
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip in suspicious_ips:
            return 'dangerous'
    return 'potential'

# Function to log threats based on classification
def log_threat(threat_type, log_message):
    if threat_type == 'potential':
        potential_threat_logger.info(log_message)
    elif threat_type == 'dangerous':
        dangerous_threat_logger.info(log_message)
    print(f"Threat Detected ({threat_type}): {log_message}")

# Function to detect suspicious packets
def is_suspicious(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else None
        protocol = packet.sprintf("%IP.proto%")
        
        # Suspicious IP detection
        if src_ip in suspicious_ips:
            return True

        # Detect port scanning (same IP accessing multiple ports)
        if src_ip not in ip_ports:
            ip_ports[src_ip] = set()
        if dst_port:
            ip_ports[src_ip].add(dst_port)
        if len(ip_ports[src_ip]) > port_scan_threshold:
            return True

        # Detect high traffic (DoS)
        if src_ip not in traffic_count:
            traffic_count[src_ip] = 0
        traffic_count[src_ip] += 1
        if traffic_count[src_ip] > traffic_threshold:
            return True

        # Suspicious protocol detection
        if protocol in suspicious_protocols:
            return True

    return False

# Main zobi
def start_sniffing():
    print("Starting packet sniffing... Press Ctrl+C to stop.")
    sniff(prn=packet_callback)

if __name__ == "__main__":
    # Start sniffier
    start_sniffing()
