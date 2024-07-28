
# NG (Next Generation) Port Scan

Next Generation Port Scan is advanced scanner that identifies open ports and gather information about target hosts using TCP/IP stack and RFC designs to help us bypass firewalls and truly understand, if port is closed or open. It supports both IPv4 and IPv6, and includes features such as logging, multi-threading, and detailed scan results.

## Why This is a Next-Generation Port Scanner

This scanner incorporates cutting-edge scanning methods that go beyond traditional port scanning. It includes innovative techniques like:

- **Inverse Mapping Scan**: Uses invalid IP headers to map out network infrastructure.
- **Bad TCP Checksum Scan**: Bypasses basic firewall checks by sending packets with incorrect checksums.
- **ACK Tunneling Scan**: Leverages the ACK flag to tunnel data, bypassing certain types of firewalls.
- **IPv6 Extension Header Scanning**: Uses IPv6 extension headers to identify network nodes that support IPv6.
- **Flow Label Scanning (IPv6)**: Exploits IPv6 flow labels for advanced probing.
- **Fragmented ICMP Scanning**: Sends fragmented ICMP packets to evade detection systems.
- **Covert Channel Scanning**: Searches for covert communication channels within a network or public facing IP using built-in Windows, Linux packet sniffer libraries.

### Bypassing Filters

Traditional scanners often get blocked by firewalls and intrusion detection systems. This next-generation scanner is designed to bypass such filters using:

- **Malformed Packets**: Sends packets with malformed headers that can slip past traditional filters.
- **Custom Fragmented TCP**: Uses custom fragmentation to avoid detection.
- **TCP Timestamp Option Manipulation**: Manipulates TCP options to fool security devices.
- **GRE and IPsec Scans**: Uses less common protocols to evade filters focused on more common protocols.
- **Randomized TTL Values**: Uses random TTL values to avoid detection by systems that expect standard patterns.

### Enhanced Success Rate

- **False Positive Elimination**: The scanner has built-in mechanisms to eliminate false positives, ensuring more accurate results.
- **Detailed Logging**: Comprehensive logging helps in analyzing scan results and troubleshooting issues.
- **Operating System Detection**: Identifies the operating system of the target, aiding in vulnerability assessments.

### Ease of Use

- **Multi-Threaded**: Utilizes multi-threading to speed up the scanning process, making it more efficient.
- **Argument Parsing**: Simple command-line arguments allow for easy customization and control of the scan.
- **Detailed Output**: Options to show detailed results, only open ports, or failed scans, providing flexibility based on user needs.
- **Plugin Descriptions**: Detailed descriptions of each scanning technique help users understand what each scan does and why it’s useful.

## Features

- Resolves target domains, IP addresses, or CIDR notation.
- Supports IPv4 and IPv6 scanning.
- Multi-threaded scanning for faster performance.
- Detailed scan results with options to show only open ports or failed scans.
- Logging of scan activities and results.
- Eliminates false positives for more accurate results.
- Supports a wide range of scanning techniques (see below).

## Requirements

- Python 3.x
- Scapy
- Tabulate
- Colorama

## Installation

Install the required Python packages using pip:

```bash
pip install scapy tabulate colorama
