# import socket
# import json
# import sys
# import os
# import ctypes
# import ipaddress
# from scapy.all import IP, TCP, UDP, sr
# import tqdm

# # Check if running as root/admin
# if sys.platform.startswith('win'):
#     # For Windows: Check if the user has administrative privileges
#     if not ctypes.windll.shell32.IsUserAnAdmin():
#         print("Warning: This script requires administrative privileges for full functionality.")
# else:
#     # For Unix-like systems: Check if the effective user ID is 0 (root)
#     if os.geteuid() != 0:
#         print("Warning: This script requires root privileges for full functionality.")

# # Load vulnerabilities from external JSON file
# with open('vulnerabilities.json', 'r') as f:
#     vulnerable_services = json.load(f)

# # Common UDP services based on port numbers
# common_udp_services = {
#     53: "dns",
#     67: "dhcp",
#     123: "ntp",
#     161: "snmp",
# }


# def scan_tcp_ports(target, ports, batch_size=100):
#     """Scan TCP ports using SYN packets and return open ports."""
#     open_ports = []
#     total_ports = len(ports)
#     with tqdm.tqdm(total=total_ports, desc="Scanning TCP ports") as pbar:
#         for i in range(0, total_ports, batch_size):
#             batch = ports[i:i + batch_size]
#             packets = [IP(dst=target) / TCP(dport=port, flags="S") for port in batch]
#             ans, _ = sr(packets, timeout=2, verbose=0)
#             for sent, received in ans:
#                 if received.haslayer(TCP) and received[TCP].flags == 0x12:  # SYN-ACK
#                     open_ports.append(sent[TCP].dport)
#             pbar.update(len(batch))
#     return open_ports


# def scan_udp_ports(target, ports, batch_size=100):
#     """Scan UDP ports and return open ports based on UDP responses."""
#     open_ports = []
#     total_ports = len(ports)
#     with tqdm.tqdm(total=total_ports, desc="Scanning UDP ports") as pbar:
#         for i in range(0, total_ports, batch_size):
#             batch = ports[i:i + batch_size]
#             packets = [IP(dst=target) / UDP(dport=port) for port in batch]
#             ans, _ = sr(packets, timeout=2, verbose=0)
#             for sent, received in ans:
#                 if received.haslayer(UDP):
#                     open_ports.append(sent[UDP].dport)
#             pbar.update(len(batch))
#     return open_ports


# def get_banner(ip, port):
#     """Attempt to grab a service banner from an open TCP port."""
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(2)
#         sock.connect((ip, port))
#         banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
#         sock.close()
#         return banner
#     except (socket.error, socket.timeout, UnicodeDecodeError):
#         return None


# def parse_service_version(banner):
#     """Parse the service and version from a banner."""
#     if not banner:
#         return "unknown", ""
#     if banner.startswith("SSH-"):
#         return "ssh", banner.split()[0][4:]
#     elif banner.startswith("220"):
#         return "ftp", banner[4:].strip()
#     elif "HTTP/" in banner:
#         return "http", banner.split()[0]
#     else:
#         return "unknown", ""


# def check_vulnerability(service, version):
#     """Check if a service and version are in the vulnerability database."""
#     if service in vulnerable_services:
#         if service == "telnet":  # Telnet is vulnerable regardless of version
#             return "Yes", vulnerable_services[service].get("", "N/A")
#         if version in vulnerable_services[service]:
#             return "Yes", vulnerable_services[service][version]
#     return "No", "N/A"


# def validate_target(target):
#     try:
#         # Check if the target is a valid IP network (CIDR notation)
#         ipaddress.ip_network(target, strict=False)
#         return True
#     except ValueError:
#         try:
#             # Check if the target is a single IP or hostname
#             socket.gethostbyname(target)
#             return True
#         except socket.gaierror:
#             return False


# def parse_ports(ports_str):
#     """Parse port string into a list of integers."""
#     try:
#         if '-' in ports_str:
#             start, end = map(int, ports_str.split('-'))
#             if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
#                 raise ValueError("Ports must be between 1 and 65535.")
#             return list(range(start, end + 1))
#         else:
#             port = int(ports_str)
#             if not 1 <= port <= 65535:
#                 raise ValueError("Port must be between 1 and 65535.")
#             return [port]
#     except ValueError as e:
#         print(f"Error: {e}")
#         sys.exit(1)


# if __name__ == "__main__":
#     # Check command-line arguments
#     if len(sys.argv) < 2:
#         print("Usage: python network-analyzer.py <target> [ports] [output_file]")
#         sys.exit(1)

#     target = sys.argv[1]
#     ports_str = sys.argv[2] if len(sys.argv) > 2 else "1-1024"  # Default port range
#     output_file = sys.argv[3] if len(sys.argv) > 3 else "scan_results.txt"

#     # Parse ports (assuming this logic exists in your script)
#     ports = []  # Replace with your port-parsing logic, e.g., converting "1-63000" to a list

#     # List to store scan results
#     results = []

#     try:
#         # Check if target is a CIDR notation
#         network = ipaddress.ip_network(target, strict=False)
#         targets = [str(ip) for ip in network.hosts()]  # Get all usable host IPs
#     except ValueError:
#         # If not CIDR, treat as a single target and validate
#         if not validate_target(target):
#             print("Error: Invalid target IP or hostname.")
#             sys.exit(1)
#         targets = [target]  # Single target as a list

#     # Scan each target
#     for target in targets:
#         print(f"Scanning target: {target}")
#         # Replace the following with your actual scanning functions
#         open_tcp_ports = scan_tcp_ports(target, ports)  # Example function
#         open_udp_ports = scan_udp_ports(target, ports)  # Example function

#         # Add results (customize based on your script's logic)
#         for port in ports:
#             if port in open_tcp_ports:
#                 results.append((target, port, "open", "TCP"))
#             else:
#                 results.append((target, port, "closed", "TCP"))
#             if port in open_udp_ports:
#                 results.append((target, port, "open", "UDP"))
#             else:
#                 results.append((target, port, "closed", "UDP"))

#     # Write results to file (customize as needed)
#     with open(output_file, "w") as f:
#         for result in results:
#             f.write(f"{result[0]}:{result[1]} - {result[2]} ({result[3]})\n")

#     print(f"Scan complete. Results saved to {output_file}")

import socket
import json
import sys
import os
import ctypes
import ipaddress
from scapy.all import IP, TCP, UDP, sr
import tqdm

# Check if running as root/admin
if sys.platform.startswith('win'):
    # For Windows: Check if the user has administrative privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Warning: This script requires administrative privileges for full functionality.")
else:
    # For Unix-like systems: Check if the effective user ID is 0 (root)
    if os.geteuid() != 0:
        print("Warning: This script requires root privileges for full functionality.")

# Load vulnerabilities from external JSON file
try:
    with open('vulnerabilities.json', 'r') as f:
        vulnerable_services = json.load(f)
except FileNotFoundError:
    print("Error: vulnerabilities.json not found. Exiting.")
    sys.exit(1)

# Common UDP services based on port numbers (Top 20 UDP ports)
common_udp_services = {
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmptrap",
    500: "isakmp",
    520: "rip",
    1900: "ssdp",
    5353: "mdns",
    631: "ipp",
    5060: "sip",
    1434: "ms-sql-m",
    5355: "llmnr",
    646: "ldp",
    69: "tftp",
    177: "xdmcp",
    19: "chargen"
}


def scan_tcp_ports(target, ports, batch_size=100):
    """Scan TCP ports using SYN packets and return open ports."""
    open_ports = []
    total_ports = len(ports)
    with tqdm.tqdm(total=total_ports, desc="Scanning TCP ports") as pbar:
        for i in range(0, total_ports, batch_size):
            batch = ports[i:i + batch_size]
            packets = [IP(dst=target) / TCP(dport=port, flags="S") for port in batch]
            ans, _ = sr(packets, timeout=2, verbose=0)
            for sent, received in ans:
                if received.haslayer(TCP) and received[TCP].flags == 0x12:  # SYN-ACK
                    open_ports.append(sent[TCP].dport)
            pbar.update(len(batch))
    return open_ports


def scan_udp_ports(target, ports, batch_size=100):
    """Scan UDP ports and return open ports based on UDP responses."""
    open_ports = []
    total_ports = len(ports)
    with tqdm.tqdm(total=total_ports, desc="Scanning UDP ports") as pbar:
        for i in range(0, total_ports, batch_size):
            batch = ports[i:i + batch_size]
            packets = [IP(dst=target) / UDP(dport=port) for port in batch]
            ans, _ = sr(packets, timeout=2, verbose=0)
            for sent, received in ans:
                if received.haslayer(UDP):
                    open_ports.append(sent[UDP].dport)
            pbar.update(len(batch))
    return open_ports


def get_banner(ip, port):
    """Attempt to grab a service banner from an open TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner
    except (socket.error, socket.timeout, UnicodeDecodeError):
        return None


def parse_service_version(banner):
    """Parse the service and version from a banner."""
    if not banner:
        return "unknown", ""
    if banner.startswith("SSH-"):
        return "ssh", banner.split()[0][4:]
    elif banner.startswith("220"):
        return "ftp", banner[4:].strip()
    elif "HTTP/" in banner:
        return "http", banner.split()[0]
    else:
        return "unknown", ""


def check_vulnerability(service, version):
    """Check if a service and version are in the vulnerability database."""
    if service in vulnerable_services:
        if service == "telnet":  # Telnet is vulnerable regardless of version
            return "Yes", vulnerable_services[service].get("", "N/A")
        if version in vulnerable_services[service]:
            return "Yes", vulnerable_services[service][version]
    return "No", "N/A"


def validate_target(target):
    try:
        # Check if the target is a valid IP network (CIDR notation)
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        try:
            # Check if the target is a single IP or hostname
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False


def parse_ports(ports_str):
    """Parse port string into a list of integers."""
    try:
        if '-' in ports_str:
            start, end = map(int, ports_str.split('-'))
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError("Ports must be between 1 and 65535.")
            return list(range(start, end + 1))
        else:
            port = int(ports_str)
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
            return [port]
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Check command-line arguments
    if len(sys.argv) < 2:
        print("Usage: python network-analyzer.py <target> [ports] [output_file]")
        sys.exit(1)

    target = sys.argv[1]
    ports_str = sys.argv[2] if len(sys.argv) > 2 else "1-1024"  # Default port range
    output_file = sys.argv[3] if len(sys.argv) > 3 else "scan_results.txt"

    ports = parse_ports(ports_str)

    results = []

    try:
        network = ipaddress.ip_network(target, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    except ValueError:
        if not validate_target(target):
            print("Error: Invalid target IP or hostname.")
            sys.exit(1)
        targets = [target]

    for target in targets:
        print(f"Scanning target: {target}")
        open_tcp_ports = scan_tcp_ports(target, ports)
        open_udp_ports = scan_udp_ports(target, ports)

        for port in ports:
            if port in open_tcp_ports:
                banner = get_banner(target, port)
                service, version = parse_service_version(banner)
                vulnerable, vulnerability_info = check_vulnerability(service, version)
                results.append((target, port, "open", "TCP", service, version, vulnerable, vulnerability_info, banner))
            else:
                results.append((target, port, "closed", "TCP", "N/A", "N/A", "N/A", "N/A", "N/A"))
            if port in open_udp_ports:
                service = common_udp_services.get(port, "unknown")
                results.append((target, port, "open", "UDP", service, "N/A", "N/A", "N/A", "N/A"))
            else:
                results.append((target, port, "closed", "UDP", "N/A", "N/A", "N/A", "N/A", "N/A")) # Corrected line

    # Write results to file
    with open(output_file, "w") as f:
        f.write("Target,Port,Status,Protocol,Service,Version,Vulnerable,Vulnerability Info,Banner\n")  # Header
        for result in results:
            f.write(f"{result[0]},{result[1]},{result[2]},{result[3]},{result[4]},{result[5]},{result[6]},{result[7]},{result[8]}\n")

    print(f"Scan complete. Results saved to {output_file}")