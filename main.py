import csv
import os
import argparse
from scapy.all import sniff
from datetime import datetime

# The Protocol Mapping Dictionary (O(1) lookup)
PROTOCOL_MAP = {
    1: "ICMP",       # IPv4 Ping and Error Messages
    2: "IGMP",       # Multicast Group Management
    4: "IPv4",       # IPv4 Encapsulation (IP-in-IP tunneling)
    6: "TCP",        # Web, File Transfer, Secure Shell
    17: "UDP",       # Streaming, DNS, Fast Multiplayer
    41: "IPv6",      # IPv6 Encapsulation
    47: "GRE",       # VPN Tunneling
    50: "ESP",       # IPsec Encryption
    51: "AH",        # IPsec Authentication
    58: "ICMPv6",    # IPv6 Ping and Neighbor Discovery
    88: "EIGRP",     # Cisco Internal Routing Protocol
    89: "OSPF",      # Open Shortest Path First Routing
    112: "VRRP",     # Virtual Router Redundancy Protocol
    132: "SCTP"      # Stream Control Transmission Protocol
}

# File Path Constant
CSV_FILE = "audit_log.csv"

def log_to_csv(timestamp, ip_version, src_ip, dst_ip, protocol):
    """
    Handles the persistent data logging. Opens the CSV in append mode ('a'),
    writes the headers if the file is brand new, and logs the packet data.
    """
    file_exists = os.path.isfile(CSV_FILE)
    
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        
        # Write the header row if this is the first time running
        if not file_exists:
            writer.writerow(["Timestamp", "IP_Version", "Source_IP", "Destination_IP", "Protocol_Details"])
            
        # Write the actual packet data
        writer.writerow([timestamp, ip_version, src_ip, dst_ip, protocol])

def packet_callback(packet):
    """
    This function is triggered every time a new packet is captured.
    It extracts basic routing information and prints it to the console.
    """
    # Grab the current time
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Checks for IPv4 
    if packet.haslayer('IP'):
        source_ip = str(packet['IP'].src)
        destination_ip = str(packet['IP'].dst)
        raw_protocol = packet['IP'].proto
        
        # Translate the integer into a readable string.
        # The .get() method safely looks up the name. If the number isn't in 
        # the Protocol Mapping Dictionary it falls back to showing "Unknown (number)".
        protocol_name = PROTOCOL_MAP.get(raw_protocol, f"UNKNOWN ({raw_protocol})")
        
        # Print a formatted log of the packet and write to CSV
        print(f"[{timestamp}] IPv4: {source_ip} -> {destination_ip} (Protocol: {protocol_name})")

        log_to_csv(timestamp, "IPv4", source_ip, destination_ip, protocol_name)

    # Checks for IPv6    
    elif packet.haslayer('IPv6'):
        source_ip = str(packet['IPv6'].src)
        destination_ip = str(packet['IPv6'].dst)
        raw_protocol = packet['IPv6'].nh

        # Translate the integer into a readable string
        protocol_name = PROTOCOL_MAP.get(raw_protocol, f"UNKNOWN ({raw_protocol})")
        
        # Print formatted log of the packet and write to CSV
        print(f"[{timestamp}] IPv6: {source_ip} -> {destination_ip} (Protocol: {protocol_name})")
        log_to_csv(timestamp, "IPv6", source_ip, destination_ip, protocol_name)

    # Catch-all for Layer 2 frames (ARP, STP, etc.)
    else:
        summary = str(packet.summary())
        print(f"[{timestamp}] Layer 2 Frame Captured: {packet.summary()}")
        # Log Layer 2 frames without breaking the CSV columns
        log_to_csv(timestamp, "Layer 2", "N/A", "N/A", summary)

def start_sniffer(packet_count, packet_filter):
    print("--- PacketAuditor: Live Sniffing Initialized ---")
    print(f"Logging data to: {os.path.abspath(CSV_FILE)}")
    print(f"Listening for traffic... (Count: {packet_count} | Filter: {packet_filter or 'None'})")
    print("-" * 50)
    
    # The core sniffing engine
    sniff(count=packet_count, filter=packet_filter, prn=packet_callback, store=False)
    
    print("-" * 50)
    print("Capture complete. Engine shutting down.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A lightweight, forensic packet sniffer.")
    
    # Add the --count argument (defaults to 20 if the user doesn't type it)
    parser.add_argument("-c", "--count", type=int, default=20, 
                        help="Number of packets to capture (default: 20)")
    
    # Add the --filter argument (defaults to capturing everything)
    parser.add_argument("-f", "--filter", type=str, default=None, 
                        help="BPF filter string (e.g., 'tcp', 'udp', 'icmp')")
    
    # Parse the commands typed into the terminal
    args = parser.parse_args()

    # Pass those commands into the engine
    start_sniffer(args.count, args.filter)