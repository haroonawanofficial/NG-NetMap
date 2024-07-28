
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

### Built-in Packet Sniffer Capabilities

- **Windows Support**: Utilizes built-in Windows packet sniffer libraries to identify the responses and create assumptions if port is open or closed of filtered.
- **Linux Support**:  Utilizes built-in Linux packet sniffer libraries to identify the responses and create assumptions if port is open or closed of filtered.
- **Mac Support**:  Utilizes built-in Mac packet sniffer libraries to identify the responses and create assumptions if port is open or closed of filtered.

## List of Built-in Plugins Using TCP/IP RFCs

- Inverse Mapping Scan: Uses the IP option to send packets with an invalid IP header.
- Bad TCP Checksum Scan: Sends TCP packets with an incorrect checksum.
- ACK Tunneling Scan: Uses the ACK flag to tunnel data.
- IPv6 Extension Header Scanning: Sends packets with IPv6 extension headers.
- Flow Label Scanning (IPv6): Scans using the IPv6 flow label.
- Flow Label Scanning (IPv4): Scans using the IPv4 flow label.
- Fragmented ICMP Scanning: Sends fragmented ICMP packets.
- Covert Channel Scanning: Scans for covert channels.
- VLAN Hopping Scan: Attempts to hop VLANs.
- Application Layer Scanning: Scans at the application layer.
- Malformed Packet Scan: Sends packets with malformed headers.
- SYN+ACK Scan: Sends SYN+ACK packets to scan.
- TCP Timestamp Option Manipulation Scan: Manipulates TCP timestamp options.
- Fragmentation Offset Manipulation Scan: Manipulates fragmentation offset.
- TCP Urgent Pointer Scan: Uses the TCP urgent pointer.
- Custom Fragmented TCP Scan: Sends custom fragmented TCP packets.
- TCP Out-of-Order Scan: Sends TCP packets out of order.
- TCP Keep-Alive Probe: Sends TCP keep-alive probes.
- GRE Scan: Scans using the GRE protocol.
- IPsec Scan: Scans using the IPsec protocol.
- IP Option Padding Scan: Sends packets with IP option padding.
- Randomized TTL Scan: Uses random TTL values for scanning.
- Reverse IP Scan: Sends packets with the source IP set to the destination IP.
- Custom IP Options Scan: Uses custom IP options for scanning.
- ICMP Source Quench Scan: Sends ICMP source quench packets.
- Custom TCP Option Scan: Uses custom TCP options for scanning.
- Custom Payload TCP Scan: Sends TCP packets with custom payloads.
- MPLS Scan: Uses MPLS labels for scanning.
- Ethernet Frame Scan: Sends Ethernet frames for scanning.
- TCP Duplicate ACK Scan: Sends duplicate TCP ACKs.

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
```

## Basic Scan

```bash
python ng-portscan.py --target example.com --ports 80,443
```

## Specifying Number of Threads

```bash
python ng-portscan.py --target example.com --ports 80,443 --threads 10
```

## Showing Detailed Results

```bash
python ng-portscan.py --target 2001:0db8:85a3:0000:0000:8a2e:0370:7334 --ports 80,443 --showdetail
```

## Showing Only Open Ports

```bash
python ng-portscan.py --target example.com --ports 80,443 --showopenport
```

## Showing Failed Plugins

```bash
python ng-portscan.py --target example.com --ports 80,443 --showfailed
```

## Showing Detailed Plugin Descriptions

```bash
python ng-portscan.py --target example.com --ports 80,443 --showplugindetail
```

## Combining Options

```bash
python ng-portscan.py --target example.com --ports 80,443 --ipv6 --showdetail --threads 20
```

## Example Usage for One Target

```bash
python ng-portscan.py --target 192.168.100.16 --ports 139 --threads 10 --showdetail --showopenport
```

## Example Usage for Multiple Targets

```bash
python ng-portscan.py --target 192.168.100.16,example1.com,example2.com --ports 139 --threads 10 --showdetail --showopenport
```

## Example Usage for CIDR

```bash
python ng-portscan.py --target 192.168.100.0/24 --ports 139 --threads 10 --showdetail --showopenport
```


## Screenshot (Linux/Mac/Windows Compatible)

![NG Port Scanner](https://i.ibb.co/YhLHK1V/ngport.png)


