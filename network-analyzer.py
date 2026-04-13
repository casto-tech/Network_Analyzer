import socket
import json
import sys
import os
import re
import ctypes
import ipaddress
import logging
import concurrent.futures
from datetime import datetime

import tqdm

# Check if running as root/admin
if sys.platform.startswith('win'):
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Warning: This script requires administrative privileges for full functionality.")
else:
    if os.geteuid() != 0:
        print("Warning: This script requires root privileges for full functionality.")

# Load vulnerabilities from the JSON file next to this script
VULN_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vulnerabilities.json')
try:
    with open(VULN_DB_PATH, 'r') as f:
        vulnerable_services = json.load(f)
except FileNotFoundError:
    print(f"Error: vulnerabilities.json not found at {VULN_DB_PATH}. Exiting.")
    sys.exit(1)

# Common UDP services keyed by port number
COMMON_UDP_SERVICES = {
    19: "chargen", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp",
    162: "snmptrap", 177: "xdmcp", 500: "isakmp", 520: "rip",
    631: "ipp", 646: "ldp", 1434: "ms-sql-m", 1900: "ssdp",
    5060: "sip", 5353: "mdns", 5355: "llmnr"
}

# TCP port-to-service hints used when banner grabbing fails
PORT_SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "mail", 53: "dns",
    80: "http", 110: "mail", 143: "imap", 389: "ldap", 443: "http",
    445: "smb", 465: "mail", 587: "mail", 636: "ldap", 993: "imap",
    995: "mail", 1194: "vpn", 1433: "database", 1521: "database",
    3306: "database", 3389: "rdp", 5060: "sip", 5432: "database",
    5900: "rdp", 6379: "database", 8080: "http", 8443: "http",
    27017: "database"
}

# Ports that speak HTTP — we send a HEAD request to get the Server header
HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888}

SEVERITY_COLORS = {
    "Critical": "\033[91m",  # bright red
    "High":     "\033[93m",  # yellow
    "Medium":   "\033[94m",  # blue
    "Low":      "\033[96m",  # cyan
}
RESET = "\033[0m"


def _color(text, severity):
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{text}{RESET}" if color else text


def _tcp_connect(target, port, timeout):
    """Try a single TCP connect; return the port number if open, else None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((target, port))
        sock.close()
        return port if err == 0 else None
    except socket.error:
        return None


def scan_tcp_ports(target, ports, timeout=1, max_workers=150):
    """Scan TCP ports via threaded connect() and return a list of open ports."""
    open_ports = []
    with tqdm.tqdm(total=len(ports), desc="Scanning TCP ports") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_tcp_connect, target, port, timeout): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
                pbar.update(1)
    return open_ports


def _udp_probe(target, port, timeout):
    """Send an empty UDP packet and return the port if the host replies."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (target, port))
        sock.recvfrom(1024)
        sock.close()
        return port
    except socket.timeout:
        return None
    except socket.error:
        return None


def scan_udp_ports(target, ports, timeout=2):
    """Probe well-known UDP service ports for responses.

    Only ports listed in COMMON_UDP_SERVICES are checked — probing arbitrary
    UDP ports with an empty packet is unreliable since most services ignore
    them, and scanning all 65535 ports would take forever.
    """
    known_ports = [p for p in ports if p in COMMON_UDP_SERVICES]
    open_ports = []
    with tqdm.tqdm(total=len(known_ports), desc="Scanning UDP ports") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(_udp_probe, target, port, timeout): port
                for port in known_ports
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
                pbar.update(1)
    return open_ports


def get_banner(ip, port):
    """Grab a service banner from an open TCP port.

    For HTTP ports a HEAD request is sent first so the Server header is
    included in the response.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        if port in HTTP_PORTS:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner or None
    except (socket.error, socket.timeout, UnicodeDecodeError):
        return None


def parse_service_version(banner, port=None):
    """Return (service, version) extracted from a banner string.

    Falls back to a port-number hint when the banner is absent or
    unrecognised.
    """
    if not banner:
        service = PORT_SERVICE_HINTS.get(port, "unknown") if port else "unknown"
        return service, ""

    # SSH  e.g. "SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu0.5"
    if banner.startswith("SSH-"):
        sw_field = banner.split()[0][4:]         # "2.0-OpenSSH_9.3p1"
        if '-' in sw_field:
            sw = sw_field.split('-', 1)[1]       # "OpenSSH_9.3p1"
            sw_lower = sw.lower()
            if sw_lower.startswith('openssh_'):
                return "ssh", "OpenSSH " + sw[8:]
            if sw_lower.startswith('dropbear_'):
                return "ssh", "Dropbear SSH " + sw[9:]
            if sw_lower.startswith('libssh_'):
                return "ssh", "libssh " + sw[7:]
            return "ssh", sw.replace('_', ' ')
        return "ssh", sw_field

    # HTTP  look for Server header in the response
    if "HTTP/" in banner or re.search(r'Server:', banner, re.IGNORECASE):
        m = re.search(r'Server:\s*(.+?)(?:\r|\n|$)', banner, re.IGNORECASE)
        if m:
            server = m.group(1).strip()
            for pattern, fmt in [
                (r'Apache/(\d[\d.]+)',           'Apache httpd {}'),
                (r'nginx/(\d[\d.]+)',            'nginx {}'),
                (r'Microsoft-IIS/(\d[\d.]+)',    'Microsoft IIS {}'),
                (r'Apache Tomcat/(\d[\d.]+)',    'Apache Tomcat {}'),
            ]:
                vm = re.search(pattern, server, re.IGNORECASE)
                if vm:
                    return "http", fmt.format(vm.group(1))
            return "http", server
        return "http", ""

    # FTP  e.g. "220 (vsFTPd 2.3.4)" or "220 ProFTPD 1.3.6 Server"
    if banner.startswith("220"):
        body = banner[4:].strip()
        for pattern, fmt in [
            (r'vsftpd\s+([\d.]+)',                    'vsftpd {}'),
            (r'ProFTPD\s+([\d.]+)',                   'ProFTPD {}'),
            (r'Pure-FTPd\s+([\d.]+)',                 'Pure-FTPd {}'),
            (r'Microsoft FTP Service(?:\s+([\d.]+))?','Microsoft IIS FTP Service {}'),
        ]:
            fm = re.search(pattern, body, re.IGNORECASE)
            if fm:
                ver = fm.group(1) if fm.lastindex and fm.group(1) else ""
                return "ftp", fmt.format(ver).strip()
        return "ftp", body

    # Telnet — port 23 always flagged regardless of banner content
    if port == 23:
        return "telnet", ""

    # SMTP / mail servers  e.g. "220 mail.example.com ESMTP Postfix"
    if re.match(r'^220\b', banner) and port in (25, 465, 587):
        body = banner[4:].strip()
        for pattern, fmt in [
            (r'Postfix(?:\s+([\d.]+))?', 'Postfix {}'),
            (r'Exim\s+([\d.]+)',         'Exim {}'),
        ]:
            fm = re.search(pattern, body, re.IGNORECASE)
            if fm:
                ver = fm.group(1) if fm.lastindex and fm.group(1) else ""
                return "mail", fmt.format(ver).strip()
        return "mail", body

    # Fall back to port hint
    service = PORT_SERVICE_HINTS.get(port, "unknown") if port else "unknown"
    return service, ""


def check_vulnerability(service, version, banner=None):
    """Look up the vulnerability database and return a list of (cve, severity) tuples.

    Entries with an empty version string in the database apply to every
    instance of that service (e.g. telnet, SNMP default community).
    Version-specific entries are matched first by exact string comparison,
    then by a normalised substring search against the raw banner.
    """
    if service not in vulnerable_services:
        return []

    results = []
    seen = set()

    for entry in vulnerable_services[service]:
        entry_version = entry.get("version", "")
        cve = entry["cve"]
        severity = entry["severity"]

        if cve in seen:
            continue

        # Version-independent — applies to all instances of this service
        if not entry_version:
            results.append((cve, severity))
            seen.add(cve)
            continue

        # Exact match against parsed version
        if version and entry_version.lower() == version.lower():
            results.append((cve, severity))
            seen.add(cve)
            continue

        # Fuzzy match: check if the DB version string appears in the raw banner
        if banner and entry_version:
            norm_banner = re.sub(r'[_/]', ' ', banner.lower())
            norm_entry  = re.sub(r'[_/]', ' ', entry_version.lower())
            if norm_entry in norm_banner:
                results.append((cve, severity))
                seen.add(cve)

    return results


def validate_target(target):
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False


def parse_ports(ports_str):
    """Parse a port specification into a deduplicated list of integers.

    Accepts a single port (``22``), a range (``1-1024``), or a
    comma-separated mix (``22,80,443,8000-8080``).
    """
    ports = []
    try:
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    raise ValueError(f"Invalid port range: {part}")
                ports.extend(range(start, end + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError(f"Port out of range: {port}")
                ports.append(port)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    # Deduplicate while preserving order
    return list(dict.fromkeys(ports))


def _fingerprint_port(target, port):
    """Banner-grab and classify a single open TCP port.

    Returns (port, service, version, vulns) so results can be collected
    from multiple threads and sorted afterwards.
    """
    banner = get_banner(target, port)
    service, version = parse_service_version(banner, port)
    vulns = check_vulnerability(service, version, banner)
    return port, service, version, vulns


def print_port_results(port, protocol, service, version, vulns):
    """Print a single port's findings to the terminal."""
    label = f"{protocol}/{port}"
    svc   = service if service != "unknown" else "unknown service"
    ver   = f" ({version})" if version else ""
    print(f"\n  [{label}]  {svc}{ver}")
    if vulns:
        for cve, severity in vulns:
            print(f"    {_color(cve, severity)}  |  Severity: {_color(severity, severity)}")
    else:
        print("    No known vulnerabilities")


def write_report(filepath, targets_data, ports, ports_str):
    """Write a Markdown vulnerability report to *filepath*.

    targets_data: list of dicts, one per target:
      {
        "target":   str,
        "tcp_open": [(port, service, version, vulns), ...],
        "udp_open": [(port, service, vulns), ...],
      }
    """
    udp_probed = sorted(p for p in ports if p in COMMON_UDP_SERVICES)

    lines = []

    # Header
    lines += [
        "# Network Vulnerability Scan Report",
        "",
        f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**TCP Ports:** {ports_str} ({len(ports)} ports scanned)  ",
        f"**UDP Ports:** {', '.join(str(p) for p in udp_probed) if udp_probed else 'none in range'}  ",
        "",
        "---",
        "",
    ]

    for entry in targets_data:
        target      = entry["target"]
        tcp_open    = entry["tcp_open"]
        udp_open    = entry["udp_open"]
        tcp_closed  = len(ports) - len(tcp_open)
        total_vulns = sum(len(v[3]) for v in tcp_open) + sum(len(v[2]) for v in udp_open)

        lines += [f"## Target: {target}", ""]

        # TCP section
        lines += ["### TCP Ports", ""]
        if tcp_open:
            for port, service, version, vulns in sorted(tcp_open, key=lambda x: x[0]):
                ver_str = f" — `{version}`" if version else ""
                lines.append(f"**Port {port}** | OPEN | Service: `{service}`{ver_str}  ")
                if vulns:
                    lines.append("**Status: VULNERABLE**  ")
                    for cve, severity in vulns:
                        lines.append(f"- {cve} | Severity: **{severity}**")
                else:
                    lines.append("**Status: No known vulnerabilities**")
                lines.append("")
        else:
            lines += ["No open TCP ports found.", ""]

        lines += [f"*Closed TCP ports: {tcp_closed}*", ""]

        # UDP section
        lines += ["### UDP Ports", ""]
        if udp_open:
            for port, service, vulns in sorted(udp_open, key=lambda x: x[0]):
                lines.append(f"**Port {port}** | OPEN | Service: `{service}`  ")
                if vulns:
                    lines.append("**Status: VULNERABLE**  ")
                    for cve, severity in vulns:
                        lines.append(f"- {cve} | Severity: **{severity}**")
                else:
                    lines.append("**Status: No known vulnerabilities**")
                lines.append("")
        else:
            lines += ["No UDP service ports responded.", ""]

        # Summary table
        lines += [
            "### Summary",
            "",
            "| | |",
            "|---|---|",
            f"| Open TCP ports | {len(tcp_open)} |",
            f"| Open UDP ports | {len(udp_open)} |",
            f"| Vulnerabilities | {'**' + str(total_vulns) + ' found**' if total_vulns else 'None found'} |",
            "",
            "---",
            "",
        ]

    with open(filepath, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python network-analyzer.py <target> [ports] [output_file]")
        print("  ports: single (22), range (1-1024), or comma-separated (22,80,443)")
        sys.exit(1)

    target_arg  = sys.argv[1]
    ports_str   = sys.argv[2] if len(sys.argv) > 2 else "1-1024"
    output_file = sys.argv[3] if len(sys.argv) > 3 else "scan_results.md"

    ports = parse_ports(ports_str)

    try:
        network = ipaddress.ip_network(target_arg, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    except ValueError:
        if not validate_target(target_arg):
            print("Error: Invalid target IP or hostname.")
            sys.exit(1)
        targets = [target_arg]

    targets_data = []

    for target in targets:
        print(f"\nScanning target: {target}")
        open_tcp_ports = scan_tcp_ports(target, ports)
        open_udp_ports = scan_udp_ports(target, ports)

        print(f"\nResults for {target}:")

        tcp_open = []
        udp_open = []

        if open_tcp_ports:
            with tqdm.tqdm(total=len(open_tcp_ports), desc="Fingerprinting TCP ports") as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    futures = {
                        executor.submit(_fingerprint_port, target, port): port
                        for port in open_tcp_ports
                    }
                    for future in concurrent.futures.as_completed(futures):
                        tcp_open.append(future.result())
                        pbar.update(1)
            tcp_open.sort(key=lambda x: x[0])

        for port in open_udp_ports:
            service = COMMON_UDP_SERVICES.get(port, "unknown")
            vulns   = check_vulnerability(service, "", None)
            udp_open.append((port, service, vulns))

        print(f"\nResults for {target}:")
        for port, service, version, vulns in tcp_open:
            print_port_results(port, "TCP", service, version, vulns)
        for port, service, vulns in udp_open:
            print_port_results(port, "UDP", service, "", vulns)

        targets_data.append({"target": target, "tcp_open": tcp_open, "udp_open": udp_open})

    write_report(output_file, targets_data, ports, ports_str)
    print(f"\nScan complete. Results saved to {output_file}")
