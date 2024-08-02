import random
import sys
import ipaddress
import logging
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, Ether, UDP, IPOption, GRE
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrRouting
from scapy.layers.l2 import Dot1Q
from scapy.contrib.mpls import MPLS
from tabulate import tabulate
from colorama import Fore, Style, init
import shutil
import json
import requests
from concurrent.futures import ThreadPoolExecutor
import pycurl
from io import BytesIO
import socket
import ssl

# Load Nmap service probes with utf-8 encoding
with open('nmap-service-probes', 'r', encoding='utf-8') as file:
    nmap_probes = file.readlines()

init(autoreset=True)

# Setup logging
logging.basicConfig(filename='scan_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Vulners API Key
VULNERS_API_KEY = "5RGD73WQQXYEQ3158QVJBE61JS0LLAR4YM9C8UV2GS7YIGOF72793JP9IBT3PQYS"

def banner_grabbing_with_nmap_probes(target_ip, target_port, retries=3, timeout=5):
    for _ in range(retries):
        try:
            probe = random.choice(nmap_probes).strip()
            if not probe or probe.startswith('#'):
                continue
            packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=probe)
            response = sr1(packet, timeout=timeout, verbose=False)
            if response and response.haslayer(Raw):
                return response[Raw].load.decode().strip()
        except Exception as e:
            logging.error(f"Error using Nmap probe on port {target_port}: {e}")
    return "Cannot find"

def load_nmap_service_probes(file_path):
    probes = []
    with open(file_path, 'r', encoding='utf-8') as f:
        probe = None
        for line in f:
            if line.startswith('#') or line.strip() == '':
                continue
            if line.startswith('Probe'):
                if probe:
                    probes.append(probe)
                probe = {'probe': line.strip(), 'matches': []}
            elif line.startswith('match'):
                match = line.strip()
                probe['matches'].append(match)
        if probe:
            probes.append(probe)
    return probes

def detect_service_from_banner(banner, probes):
    for probe in probes:
        for match in probe['matches']:
            pattern = re.compile(r'match\s+.+?\s+m/(?P<pattern>.+?)/')
            m = pattern.search(match)
            if m:
                regex = m.group('pattern')
                if re.search(regex, banner):
                    service = match.split()[1]
                    return service
    return "Unknown"


probes = load_nmap_service_probes('nmap-service-probes')

# Plugin descriptions
plugins = {
    "Inverse Mapping Scan": "Uses the IP option to send packets with an invalid IP header.",
    "Bad TCP Checksum Scan": "Sends TCP packets with an incorrect checksum.",
    "ACK Tunneling Scan": "Uses the ACK flag to tunnel data.",
    "IPv6 Extension Header Scanning": "Sends packets with IPv6 extension headers.",
    "Flow Label Scanning (IPv6)": "Scans using the IPv6 flow label.",
    "Flow Label Scanning (IPv4)": "Scans using the IPv4 flow label.",
    "Fragmented ICMP Scanning": "Sends fragmented ICMP packets.",
    "Covert Channel Scanning": "Scans for covert channels.",
    "VLAN Hopping Scan": "Attempts to hop VLANs.",
    "Application Layer Scanning": "Scans at the application layer.",
    "Malformed Packet Scan": "Sends packets with malformed headers.",
    "SYN+ACK Scan": "Sends SYN+ACK packets to scan.",
    "TCP Timestamp Option Manipulation Scan": "Manipulates TCP timestamp options.",
    "Fragmentation Offset Manipulation Scan": "Manipulates fragmentation offset.",
    "TCP Urgent Pointer Scan": "Uses the TCP urgent pointer.",
    "Custom Fragmented TCP Scan": "Sends custom fragmented TCP packets.",
    "TCP Out-of-Order Scan": "Sends TCP packets out of order.",
    "TCP Keep-Alive Probe": "Sends TCP keep-alive probes.",
    "GRE Scan": "Scans using the GRE protocol.",
    "IPsec Scan": "Scans using the IPsec protocol.",
    "IP Option Padding Scan": "Sends packets with IP option padding.",
    "Randomized TTL Scan": "Uses random TTL values for scanning.",
    "Reverse IP Scan": "Sends packets with the source IP set to the destination IP.",
    "Custom IP Options Scan": "Uses custom IP options for scanning.",
    "ICMP Source Quench Scan": "Sends ICMP source quench packets.",
    "Custom TCP Option Scan": "Uses custom TCP options for scanning.",
    "Custom Payload TCP Scan": "Sends TCP packets with custom payloads.",
    "MPLS Scan": "Uses MPLS labels for scanning.",
    "Ethernet Frame Scan": "Sends Ethernet frames for scanning.",
    "TCP Duplicate ACK Scan": "Sends duplicate TCP ACKs.",
    "Randomized Source IP and Port": "Use multiple source IP addresses (spoofing) and source ports to make detection harder.",
    "Randomized Payloads": "Insert random data into the packet payloads to make them appear different.",
    "Variable Packet Sizes": "Use different packet sizes to avoid patterns.",
    "TCP Timestamp Manipulation": "Modify TCP timestamp options.",
    "IP Option Fields Manipulation": "Use various IP options to diversify the packets.",
    "Decoy Packets": "Send decoy packets along with the real ones to confuse detection systems.",
    "Protocol Mix": "Mix different protocols in the scan to create noise.",
    "Adaptive Timing": "Dynamically adjust the timing based on the network response."
}

def resolve_target(target):
    try:
        ip_address = socket.gethostbyname(target)
        logging.info(f"Resolved {target} to {ip_address}")
        return ip_address
    except socket.gaierror:
        logging.error(f"Failed to resolve {target}")
        return target

def ipv4_to_ipv6(ipv4_address):
    ipv4 = ipaddress.IPv4Address(ipv4_address)
    ipv6 = ipaddress.IPv6Address('::ffff:{}'.format(ipv4))
    return str(ipv6)

def parse_arguments():
    import argparse
    parser = argparse.ArgumentParser(description='Custom TCP/IP Scanner')
    parser.add_argument('--target', required=True, help='Target domain, IP address, or CIDR notation (comma-separated)')
    parser.add_argument('--ports', required=True, help='Comma-separated list of target ports')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use for scanning')
    parser.add_argument('--ipv6', action='store_true', help='Use IPv6 for scanning')
    parser.add_argument('--showdetail', action='store_true', help='Show detailed scan results')
    parser.add_argument('--showopenport', action='store_true', help='Show only open ports in the results')
    parser.add_argument('--showfailed', action='store_true', help='Show failed scan plugins')
    parser.add_argument('--showplugindetail', action='store_true', help='Show detailed plugin descriptions')
    parser.add_argument('--networkscan', action='store_true', help='Scan entire network and detect segments')
    parser.add_argument('--publicscan', action='store_true', help='Scan public-facing IP addresses')
    parser.add_argument('--vulners', action='store_true', help='Use Vulners to find vulnerabilities')
    args = parser.parse_args()
    
    # Correctly parse targets and ports
    targets = args.target.split(',')
    target_ports = [int(port) for port in args.ports.split(',')]
    
    return targets, target_ports, args.threads, args.ipv6, args.showdetail, args.showopenport, args.showfailed, args.showplugindetail, args.networkscan, args.publicscan, args.vulners

def is_ip_alive(target_ip):
    try:
        packet = IP(dst=target_ip)/ICMP()
        response = sr1(packet, timeout=1, verbose=False)
        return response is not None
    except Exception as e:
        logging.error(f"Error checking if IP is alive: {e}")
        return False

def get_domain_name(target_ip):
    try:
        return socket.gethostbyaddr(target_ip)[0]
    except socket.herror:
        return "Unknown"

def get_os_from_response(response):
    try:
        if response is None:
            return "Unknown"
        if response.haslayer(TCP):
            ttl = response[IP].ttl
            if ttl <= 64:
                return "Linux"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown"
        return "Unknown"
    except Exception as e:
        logging.error(f"Error detecting OS from response: {e}")
        return "Unknown"

def tcp_connect_scan(target_ip, target_port):
    try:
        logging.info(f"Performing TCP Connect Scan on {target_ip}:{target_port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, target_port))
        sock.close()
        return result == 0  # Return True if the port is open
    except Exception as e:
        logging.error(f"Error performing TCP Connect Scan: {e}")
        return False

def banner_grabbing(target_ip, target_port, retries=3, timeout=5):
    banners = []
    for _ in range(retries):
        try:
            # Attempt to grab the banner using a raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, target_port))
            sock.send(b'\r\n')
            response = sock.recv(1024).decode().strip()
            banners.append(response)
            sock.close()
            break  # Exit loop if banner is successfully grabbed
        except Exception as e:
            logging.error(f"Error grabbing banner on port {target_port} using raw socket: {e}")

    if not banners:
        for _ in range(retries):
            try:
                # Attempt to grab the banner using a socket with context manager
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((target_ip, target_port))
                    banner = s.recv(1024).decode().strip()
                    banners.append(banner)
                    break  # Exit loop if banner is successfully grabbed
            except Exception as e:
                logging.error(f"Error grabbing banner on port {target_port}: {e}")

    if not banners and target_port in [80, 443]:  # If Cannot find was grabbed using socket, try using pycurl for HTTP/HTTPS
        for _ in range(retries):
            try:
                buffer = BytesIO()
                c = pycurl.Curl()
                url = f"http://{target_ip}:{target_port}" if target_port == 80 else f"https://{target_ip}:{target_port}"
                c.setopt(c.URL, url)
                c.setopt(c.WRITEDATA, buffer)
                c.setopt(c.CONNECTTIMEOUT, 5)
                c.setopt(c.TIMEOUT, 10)
                c.perform()
                response = buffer.getvalue().decode('utf-8').strip()
                banners.append(response)
                c.close()
                break  # Exit loop if banner is successfully grabbed
            except Exception as e:
                logging.error(f"Error grabbing banner on port {target_port} using pycurl: {e}")

    return "\n".join(banners) if banners else "Cannot find"

def perform_scan(scan_type, packet, target_ip, target_port, src_ip=None, use_vulners=False):
    try:
        logging.info(f"Performing {scan_type} on {target_ip}:{target_port}")
        if src_ip:
            packet[IP].src = src_ip
        response = sr1(packet, timeout=1, verbose=False)
        os_detected = get_os_from_response(response)
        domain = get_domain_name(target_ip)
        port_open = tcp_connect_scan(target_ip, target_port)
        port_response = "Open" if port_open else "Closed"
        scan_success = "Yes" if response else "No"
        advanced_packet_response = response.summary() if response else "No response"
        banner = banner_grabbing_with_nmap_probes(target_ip, target_port) if port_open else "Cannot find"
        service = detect_service_from_banner(banner, probes)
        vulnerabilities = get_vulnerabilities(banner) if use_vulners and port_open else "No vulnerabilities"
        log_scan_result(scan_type, target_ip, target_port, domain, response, os_detected, port_response, scan_success, packet, response, banner, service, vulnerabilities)
        return [scan_type, advanced_packet_response, os_detected, target_ip, domain, target_port, port_response, scan_success, packet.summary(), response.summary() if response else "No response", banner, service, vulnerabilities]
    except Exception as e:
        logging.error(f"Error performing scan {scan_type} on {target_ip}:{target_port}: {e}")
        return [scan_type, "Error", "Unknown", target_ip, "Unknown", target_port, "Error", "No", "Error", "Error", "Cannot find", "Unknown", "No vulnerabilities"]

def get_vulnerabilities(banner):
    try:
        headers = {'Content-Type': 'application/json'}
        data = {'apiKey': VULNERS_API_KEY, 'software': banner}
        response = requests.post('https://vulners.com/api/v3/search/lucene/', headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            vulnerabilities = response.json().get('data', {}).get('search', {}).get('documents', [])
            if vulnerabilities:
                vulns = []
                for vuln in vulnerabilities:
                    vulns.append(vuln['title'] + ' - ' + vuln['description'])
                return '\n'.join(vulns)
            else:
                return "No vulnerabilities found"
        return "Error fetching vulnerabilities"
    except Exception as e:
        logging.error(f"Error fetching vulnerabilities: {e}")
        return "Error fetching vulnerabilities"

def log_scan_result(scan_type, target_ip, target_port, domain, response, os_detected, port_response, scan_success, packet, response_packet, banner, detected_service, vulnerabilities):
    logging.info(f"Scan Type: {scan_type}")
    logging.info(f"Response: {response.summary() if response else 'No response'}")
    logging.info(f"Operating System: {os_detected}")
    logging.info(f"IP: {target_ip}")
    logging.info(f"Domain: {domain}")
    logging.info(f"Port: {target_port}")
    logging.info(f"Port Response: {port_response}")
    logging.info(f"Scan Success: {scan_success}")
    logging.info(f"Packet Sent: {packet.summary()}")
    logging.info(f"Packet Received: {response_packet.summary() if response_packet else 'No response'}")
    logging.info(f"Banner: {banner}")
    logging.info(f"Detected Service: {detected_service}")
    logging.info(f"Vulnerabilities: {vulnerabilities}")
    logging.info("-" * 50)

def print_scan_results(scan_results, show_detail, show_open_port, show_failed):
    headers = [
        Fore.CYAN + "Scan Type" + Style.RESET_ALL,
        Fore.CYAN + "Advanced Packet Response" + Style.RESET_ALL,
        Fore.CYAN + "Operating System" + Style.RESET_ALL,
        Fore.CYAN + "IP" + Style.RESET_ALL,
        Fore.CYAN + "Domain" + Style.RESET_ALL,
        Fore.CYAN + "Port" + Style.RESET_ALL,
        Fore.CYAN + "Port Response" + Style.RESET_ALL,
        Fore.CYAN + "Scan Success" + Style.RESET_ALL,
#        Fore.CYAN + "Packet Sent" + Style.RESET_ALL,
#        Fore.CYAN + "Packet Received" + Style.RESET_ALL,
        Fore.CYAN + "Banner" + Style.RESET_ALL,
        Fore.CYAN + "Vulnerabilities" + Style.RESET_ALL,
#        Fore.CYAN + "Timestamp" + Style.RESET_ALL
    ]
    
    table = []
    for item in scan_results:
        if len(item) >= 13:  # Check if the item has enough elements
            row = [
                Fore.GREEN + str(item[0]) + Style.RESET_ALL if item[7] == "Yes" else Fore.RED + str(item[0]) + Style.RESET_ALL,
                item[1],
                item[2],
                item[3],
                item[4],
                item[5],
                item[6],
                Fore.GREEN + item[7] + Style.RESET_ALL if item[7] == "Yes" else Fore.RED + item[7] + Style.RESET_ALL,
                item[8],
                item[9],
                item[10],
                item[11],
                item[12],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ]
            if show_detail or item[6] == "Open":  # Show detailed or only open ports
                table.append(row)
        else:
            logging.error(f"Incomplete scan result: {item}")  # Optional: log incomplete results
    
    if table:
        terminal_width = shutil.get_terminal_size().columns
        print(tabulate(table, headers=headers, tablefmt="grid", maxcolwidths=[terminal_width // len(headers)]))
    else:
        print("No scan results to display based on the current filter settings.")


def eliminate_false_positives(responses):
    valid_responses = []
    for response in responses:
        if response[1] != "No response" and response[7] == "Yes":
            valid_responses.append(response)
    return valid_responses

# Define scanning functions with reliable port status checks
def inverse_mapping_scan(target_ip, target_port):
    packet = IP(dst=target_ip, options=[IPOption(b'\x83\x03\x03')])/ICMP()
    return perform_scan("Inverse Mapping Scan", packet, target_ip, target_port)

def bad_tcp_checksum_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, chksum=0x1234)
    return perform_scan("Bad TCP Checksum Scan", packet, target_ip, target_port)

def ack_tunneling_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(flags="A", ack=0)
    return perform_scan("ACK Tunneling Scan", packet, target_ip, target_port)

def ipv6_extension_header_scanning(target_ipv6, target_port):
    packet = IPv6(dst=target_ipv6)/IPv6ExtHdrRouting()/ICMPv6EchoRequest()
    return perform_scan("IPv6 Extension Header Scanning", packet, target_ipv6, target_port)

def flow_label_scanning_ipv6(target_ipv6, target_port):
    packet = IPv6(dst=target_ipv6, fl=12345)/ICMPv6EchoRequest()
    return perform_scan("Flow Label Scanning (IPv6)", packet, target_ipv6, target_port)

def flow_label_scanning_ipv4(target_ip, target_port):
    packet = IP(dst=target_ip, tos=0x28)/ICMP()
    return perform_scan("Flow Label Scanning (IPv4)", packet, target_ip, target_port)

def fragmented_icmp_scanning(target_ip, target_port):
    packet = IP(dst=target_ip, flags="MF")/ICMP()/("X"*60000)
    return perform_scan("Fragmented ICMP Scanning", packet, target_ip, target_port)

def covert_channel_scanning(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port)/("X"*20)
    return perform_scan("Covert Channel Scanning", packet, target_ip, target_port)

def vlan_hopping_scan(target_ip, target_port):
    packet = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=2)/IP(dst=target_ip)/ICMP()
    return perform_scan("VLAN Hopping Scan", packet, target_ip, target_port)

def application_layer_scanning(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load="GET / HTTP/1.1\r\nHost: "+target_ip+"\r\n\r\n")
    return perform_scan("Application Layer Scanning", packet, target_ip, target_port)

def malformed_packet_scan(target_ip, target_port):
    packet = IP(dst=target_ip, ihl=2, version=3)/ICMP()
    return perform_scan("Malformed Packet Scan", packet, target_ip, target_port)

def syn_ack_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="SA")
    return perform_scan("SYN+ACK Scan", packet, target_ip, target_port)

def tcp_timestamp_option_manipulation_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, options=[('Timestamp', (123, 0))])
    return perform_scan("TCP Timestamp Option Manipulation Scan", packet, target_ip, target_port)

def fragmentation_offset_manipulation_scan(target_ip, target_port):
    packet = IP(dst=target_ip, frag=64)/ICMP()
    return perform_scan("Fragmentation Offset Manipulation Scan", packet, target_ip, target_port)

def tcp_urgent_pointer_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, urgptr=0xFFFF)
    return perform_scan("TCP Urgent Pointer Scan", packet, target_ip, target_port)

def custom_fragmented_tcp_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")/("X"*60000)
    return perform_scan("Custom Fragmented TCP Scan", packet, target_ip, target_port)

def tcp_out_of_order_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, seq=1000)
    return perform_scan("TCP Out-of-Order Scan", packet, target_ip, target_port)

def tcp_keep_alive_probe(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="A")
    return perform_scan("TCP Keep-Alive Probe", packet, target_ip, target_port)

def gre_scan(target_ip, target_port):
    packet = IP(dst=target_ip, proto=47)/GRE()
    return perform_scan("GRE Scan", packet, target_ip, target_port)

def ipsec_scan(target_ip, target_port):
    packet = IP(dst=target_ip, proto=50)/("X"*20)
    return perform_scan("IPsec Scan", packet, target_ip, target_port)

def ip_option_padding_scan(target_ip, target_port):
    packet = IP(dst=target_ip, options=[IPOption(b'\x83\x03\x03'), IPOption(b'\x00'*40)])/ICMP()
    return perform_scan("IP Option Padding Scan", packet, target_ip, target_port)

def randomized_ttl_scan(target_ip, target_port):
    ttl_value = random.randint(1, 255)
    packet = IP(dst=target_ip, ttl=ttl_value)/ICMP()
    return perform_scan("Randomized TTL Scan", packet, target_ip, target_port)

def reverse_ip_scan(target_ip, target_port):
    packet = IP(dst=target_ip, src=target_ip)/ICMP()
    return perform_scan("Reverse IP Scan", packet, target_ip, target_port)

def custom_ip_options_scan(target_ip, target_port):
    packet = IP(dst=target_ip, options=[IPOption(b'\x82\x04\x00\x00')])/ICMP()
    return perform_scan("Custom IP Options Scan", packet, target_ip, target_port)

def icmp_source_quench_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/ICMP(type=4)
    return perform_scan("ICMP Source Quench Scan", packet, target_ip, target_port)

def custom_tcp_option_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, options=[(0x42, b'\x01\x02\x03\x04')])
    return perform_scan("Custom TCP Option Scan", packet, target_ip, target_port)

def custom_payload_tcp_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load="CustomPayload")
    return perform_scan("Custom Payload TCP Scan", packet, target_ip, target_port)

def mpls_scan(target_ip, target_port):
    packet = Ether()/MPLS(label=3, cos=5, s=1, ttl=64)/IP(dst=target_ip)/ICMP()
    return perform_scan("MPLS Scan", packet, target_ip, target_port)

def ethernet_frame_scan(target_ip, target_port):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=target_ip)/ICMP()
    return perform_scan("Ethernet Frame Scan", packet, target_ip, target_port)

def tcp_duplicate_ack_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="A", ack=1)
    send(packet, verbose=False)
    response = sr1(packet, timeout=1, verbose=False)
    return perform_scan("TCP Duplicate ACK Scan", packet, target_ip, target_port)

# Advanced scanning methods
def randomized_source_ip_and_port_scan(target_ip, target_port):
    src_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    src_port = random.randint(1024, 65535)
    packet = IP(src=src_ip, dst=target_ip)/TCP(sport=src_port, dport=target_port)
    return perform_scan("Randomized Source IP and Port", packet, target_ip, target_port, src_ip=src_ip)

def randomized_payloads_scan(target_ip, target_port):
    payload = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=64))
    packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=payload)
    return perform_scan("Randomized Payloads", packet, target_ip, target_port)

def variable_packet_sizes_scan(target_ip, target_port):
    size = random.randint(64, 1500)
    packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load='X'*size)
    return perform_scan("Variable Packet Sizes", packet, target_ip, target_port)

def tcp_timestamp_manipulation_scan(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, options=[('Timestamp', (random.randint(1, 10000), 0))])
    return perform_scan("TCP Timestamp Manipulation", packet, target_ip, target_port)

def ip_option_fields_manipulation_scan(target_ip, target_port):
    packet = IP(dst=target_ip, options=[IPOption(b'\x82\x04\x00\x00')])/TCP(dport=target_port)
    return perform_scan("IP Option Fields Manipulation", packet, target_ip, target_port)

def decoy_packets_scan(target_ip, target_port):
    decoy_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    packet = IP(dst=target_ip)/TCP(dport=target_port)
    decoy_packet = IP(src=decoy_ip, dst=target_ip)/TCP(dport=target_port)
    perform_scan("Decoy Packets", decoy_packet, target_ip, target_port, src_ip=decoy_ip)
    return perform_scan("Decoy Packets", packet, target_ip, target_port)

def protocol_mix_scan(target_ip, target_port):
    protocols = [TCP(dport=target_port), UDP(dport=target_port), ICMP()]
    packet = IP(dst=target_ip)/random.choice(protocols)
    return perform_scan("Protocol Mix", packet, target_ip, target_port)

def adaptive_timing_scan(target_ip, target_port):
    delay = random.uniform(0.5, 2.0)
    packet = IP(dst=target_ip)/TCP(dport=target_port)
    response = sr1(packet, timeout=delay, verbose=False)
    return perform_scan("Adaptive Timing", packet, target_ip, target_port)

def network_scan(targets, target_ports, max_threads, use_vulners):
    scan_results = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for target in targets:
            for port in target_ports:
                futures.append(executor.submit(randomized_source_ip_and_port_scan, target, port))
                futures.append(executor.submit(randomized_payloads_scan, target, port))
                futures.append(executor.submit(variable_packet_sizes_scan, target, port))
                futures.append(executor.submit(tcp_timestamp_manipulation_scan, target, port))
                futures.append(executor.submit(ip_option_fields_manipulation_scan, target, port))
                futures.append(executor.submit(decoy_packets_scan, target, port))
                futures.append(executor.submit(protocol_mix_scan, target, port))
                futures.append(executor.submit(adaptive_timing_scan, target, port))
        for future in futures:
            scan_results.append(future.result())
    return scan_results

def print_summary(successful_plugins, open_ports_summary, failed_plugins, show_failed, show_plugin_detail, evasion_techniques, ip_status):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary_headers = [Fore.CYAN + "Description" + Style.RESET_ALL, Fore.CYAN + "Details" + Style.RESET_ALL]
    summary_table = [
        ["Total plugins loaded", len(plugins)],
        ["Total plugins successful", len(successful_plugins)]
    ]

    unique_successful_plugins = set(successful_plugins)
    unique_failed_plugins = set(failed_plugins)
    
    for plugin in unique_successful_plugins:
        summary_table.append([f"Plugin successful", plugin])
    
    summary_table.append(["Total open ports found", sum(len(ports) for ports in open_ports_summary.values())])
    
    for ip, ports in open_ports_summary.items():
        summary_table.append([f"Open ports on {ip}", ', '.join(map(str, ports))])
    
    if show_failed:
        summary_table.append(["Total plugins failed", len(unique_failed_plugins)])
        for plugin in unique_failed_plugins:
            summary_table.append([f"Plugin failed", plugin])

    summary_table.append(["Scan log saved to", "scan_log.txt"])

    print(tabulate(summary_table, headers=summary_headers, tablefmt="grid"))

    # Print plugin details
    if show_plugin_detail:
        print("\nExtra detail plugins description detail\n")
        plugin_headers = [Fore.CYAN + "Plugin" + Style.RESET_ALL, Fore.CYAN + "Description" + Style.RESET_ALL]
        plugin_table = [[plugin, description] for plugin, description in plugins.items() if plugin in unique_successful_plugins or plugin in unique_failed_plugins]
        print(tabulate(plugin_table, headers=plugin_headers, tablefmt="grid"))

    # Print evasion techniques details
    print("\nIDS/IPS Evasion Techniques Used\n")
    evasion_headers = [Fore.CYAN + "Technique" + Style.RESET_ALL, Fore.CYAN + "Details" + Style.RESET_ALL]
    print(tabulate(evasion_techniques, headers=evasion_headers, tablefmt="grid"))

    # Print IP status details
    print("\nIP Status and Firewall Detection\n")
    ip_status_headers = [Fore.CYAN + "IP" + Style.RESET_ALL, Fore.CYAN + "Status" + Style.RESET_ALL, Fore.CYAN + "Segment" + Style.RESET_ALL, Fore.CYAN + "Firewall Detected" + Style.RESET_ALL]
    print(tabulate(ip_status, headers=ip_status_headers, tablefmt="grid"))

def main():
    targets, target_ports, max_threads, use_ipv6, show_detail, show_open_port, show_failed, show_plugin_detail, networkscan, publicscan, use_vulners = parse_arguments()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - Number of targets entered: {len(targets)}")
    print(f"{timestamp} - Targets: {', '.join(targets)}")
    print(f"{timestamp} - Number of ports entered: {len(target_ports)}")
    print(f"{timestamp} - Enumerating Ports: {', '.join(map(str, target_ports))}")
    
    all_scan_results = []
    evasion_techniques = []
    ip_status = []

    for target in targets:
        target_ip = resolve_target(target)
        target_ipv6 = target_ip
        try:
            segment = "Same segment" if ipaddress.ip_network(target_ip, strict=False).subnet_of(ipaddress.ip_network(resolve_target(targets[0]), strict=False)) else "Different segment"
        except ValueError:
            segment = "Unknown segment"
        firewall_detected = "No"

        # Convert IPv4 to IPv6 if needed
        if use_ipv6:
            try:
                ipaddress.IPv6Address(target_ip)
                target_ipv6 = target_ip
            except ipaddress.AddressValueError:
                target_ipv6 = ipv4_to_ipv6(target_ip)
    
        logging.info(f"Starting scans on {target_ip} ({target})")
        if is_ip_alive(target_ip):
            logging.info(f"Target {target_ip} is alive")
            ip_status.append([target_ip, "Online", segment, firewall_detected])
            scan_results = []
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for port in target_ports:
                    print(f"{Fore.YELLOW}Scanning port {port} on {target_ip} ({target})...{Style.RESET_ALL}")
                    futures.append(executor.submit(inverse_mapping_scan, target_ip, port))
                    futures.append(executor.submit(bad_tcp_checksum_scan, target_ip, port))
                    futures.append(executor.submit(ack_tunneling_scan, target_ip, port))
                    if ':' in target_ipv6:
                        futures.append(executor.submit(ipv6_extension_header_scanning, target_ipv6, port))
                        futures.append(executor.submit(flow_label_scanning_ipv6, target_ipv6, port))
                    futures.append(executor.submit(flow_label_scanning_ipv4, target_ip, port))
                    futures.append(executor.submit(fragmented_icmp_scanning, target_ip, port))
                    futures.append(executor.submit(covert_channel_scanning, target_ip, port))
                    futures.append(executor.submit(vlan_hopping_scan, target_ip, port))
                    futures.append(executor.submit(application_layer_scanning, target_ip, port))
                    futures.append(executor.submit(malformed_packet_scan, target_ip, port))
                    futures.append(executor.submit(syn_ack_scan, target_ip, port))
                    futures.append(executor.submit(tcp_timestamp_option_manipulation_scan, target_ip, port))
                    futures.append(executor.submit(fragmentation_offset_manipulation_scan, target_ip, port))
                    futures.append(executor.submit(tcp_urgent_pointer_scan, target_ip, port))
                    futures.append(executor.submit(custom_fragmented_tcp_scan, target_ip, port))
                    futures.append(executor.submit(tcp_out_of_order_scan, target_ip, port))
                    futures.append(executor.submit(tcp_keep_alive_probe, target_ip, port))
                    futures.append(executor.submit(gre_scan, target_ip, port))
                    futures.append(executor.submit(ipsec_scan, target_ip, port))
                    futures.append(executor.submit(ip_option_padding_scan, target_ip, port))
                    futures.append(executor.submit(randomized_ttl_scan, target_ip, port))
                    futures.append(executor.submit(reverse_ip_scan, target_ip, port))
                    futures.append(executor.submit(custom_ip_options_scan, target_ip, port))
                    futures.append(executor.submit(icmp_source_quench_scan, target_ip, port))
                    futures.append(executor.submit(custom_tcp_option_scan, target_ip, port))
                    futures.append(executor.submit(custom_payload_tcp_scan, target_ip, port))
                    futures.append(executor.submit(mpls_scan, target_ip, port))
                    futures.append(executor.submit(ethernet_frame_scan, target_ip, port))
                    futures.append(executor.submit(tcp_duplicate_ack_scan, target_ip, port))
                    
                    # Collect evasion techniques used
                    evasion_techniques.append(["Randomized Source IP and Port", f"Target: {target_ip}, Port: {port}"])
                    evasion_techniques.append(["Randomized Payloads", f"Target: {target_ip}, Port: {port}"])
                    evasion_techniques.append(["Variable Packet Sizes", f"Target: {target_ip}, Port: {port}"])
                    evasion_techniques.append(["TCP Timestamp Manipulation", f"Target: {target_ip}, Port: {port}"])
                    evasion_techniques.append(["IP Option Fields Manipulation", f"Target: {target_ip}, Port: {port}"])
                    evasion_techniques.append(["Decoy Packets", f"Target: {target_ip}, Port: {port}"])
                    evasion_techniques.append(["Protocol Mix", f"Target: {target_ip}, Port: {port}"])
                    evasion_techniques.append(["Adaptive Timing", f"Target: {target_ip}, Port: {port}"])

                for future in futures:
                    scan_results.append(future.result())
    
            scan_results = eliminate_false_positives(scan_results)
            print_scan_results(scan_results, show_detail, show_open_port, show_failed)
            all_scan_results.extend(scan_results)
            logging.info(f"Completed scans on {target_ip} ({target})")
        else:
            logging.warning(f"Target {target_ip} ({target}) is not alive")
            ip_status.append([target_ip, "Offline", segment, firewall_detected])
    
    if networkscan or publicscan:
        network_scan_results = network_scan(targets, target_ports, max_threads, use_vulners)
        all_scan_results.extend(network_scan_results)
    
    open_ports_summary = {}
    successful_plugins = []
    failed_plugins = []
    for result in all_scan_results:
        if result[6] == "Open":
            if result[3] not in open_ports_summary:
                open_ports_summary[result[3]] = []
            if result[5] not in open_ports_summary[result[3]]:
                open_ports_summary[result[3]].append(result[5])
        if result[7] == "Yes":
            successful_plugins.append(result[0])
        else:
            failed_plugins.append(result[0])
    
    print_summary(successful_plugins, open_ports_summary, failed_plugins, show_failed, show_plugin_detail, evasion_techniques, ip_status)

if __name__ == "__main__":
    main()
