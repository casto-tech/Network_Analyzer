import socket
import json
import sys
import os
import re
import ssl
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

# ── Port / service mappings ──────────────────────────────────────────────────

# Ports where a TLS handshake must happen before any data is exchanged
TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 993, 995, 3269, 5061, 8443}

# Ports where we send an HTTP HEAD request to retrieve the Server header
HTTP_PORTS = {
    80, 443,            # Standard
    3000, 5000, 5173,   # Dev Frameworks
    8000, 8008, 8080,   # Common Alternatives
    8081, 8443, 8888,   # Alternatives/Proxies
    9000, 9090          # Monitoring/Management
}

# Well-known UDP services; only these are probed during a UDP scan
COMMON_UDP_SERVICES = {
    19: "chargen", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp",
    162: "snmptrap", 177: "xdmcp", 500: "isakmp", 520: "rip",
    631: "ipp", 646: "ldp", 1434: "ms-sql-m", 1900: "ssdp",
    5060: "sip", 5353: "mdns", 5355: "llmnr",
}

# Service-specific UDP payloads; empty bytes used as a fallback
UDP_PROBES = {
    # DNS — standard A-record query for "version.bind" (elicits a response
    # from any recursive or authoritative resolver)
    53: (
        b'\xaa\xbb'              # Transaction ID
        b'\x01\x00'              # Flags: standard query, recursion desired
        b'\x00\x01'              # QDCOUNT: 1 question
        b'\x00\x00\x00\x00\x00\x00'  # ANCOUNT / NSCOUNT / ARCOUNT
        b'\x07version\x04bind\x00'
        b'\x00\x10'              # QTYPE: TXT
        b'\x00\x03'              # QCLASS: CHAOS
    ),
    # NTP — mode 3 client request (48 bytes, version 3)
    123: bytes([0x1b] + [0] * 47),
}

# TCP port → service name; used when banner grabbing yields nothing
PORT_SERVICE_HINTS = {
    21: "ftp",       22: "ssh",      23: "telnet",   25: "mail",
    53: "dns",       80: "http",    110: "mail",    143: "imap",
    389: "ldap",    443: "http",   445: "smb",     465: "mail",
    587: "mail",    636: "ldap",   993: "imap",    995: "mail",
    1194: "vpn",   1433: "database", 1521: "database",
    3306: "database", 3389: "rdp", 5060: "sip",
    5432: "database", 5900: "rdp", 6379: "database",
    8080: "http",  8443: "http",  27017: "database",
}

# ── Terminal colours ─────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical": "\033[91m",
    "High":     "\033[93m",
    "Medium":   "\033[94m",
    "Low":      "\033[96m",
}
RESET = "\033[0m"


def _color(text, severity):
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{text}{RESET}" if color else text


# ── Scanning ─────────────────────────────────────────────────────────────────

def _tcp_probe(target, port, connect_timeout, banner_timeout):
    """Open one TCP connection, grab the banner, and return scan results.

    Combines the connect and fingerprint steps so each port uses exactly one
    socket.  Returns (port, service, version, vulns) when the port is open,
    or None when it is closed / filtered.
    """
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(connect_timeout)
        if raw_sock.connect_ex((target, port)) != 0:
            raw_sock.close()
            return None

        # Port is open — switch to a longer timeout for banner reading
        raw_sock.settimeout(banner_timeout)

        # Upgrade to TLS for encrypted ports
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(raw_sock, server_hostname=target)
            except ssl.SSLError:
                sock = raw_sock          # fall back to plaintext on TLS failure
        else:
            sock = raw_sock

        # For HTTP ports send a HEAD request so the Server header is returned
        if port in HTTP_PORTS:
            try:
                sock.sendall(
                    b"HEAD / HTTP/1.0\r\n"
                    b"Host: " + target.encode() + b"\r\n"
                    b"User-Agent: NetworkAnalyzer/1.0\r\n\r\n"
                )
            except (socket.error, ssl.SSLError):
                pass

        # Read up to 4 KB of banner / response data
        try:
            banner = sock.recv(4096).decode('utf-8', errors='ignore').strip() or None
        except (socket.timeout, socket.error, ssl.SSLError):
            banner = None

        try:
            sock.close()
        except Exception:
            pass

        service, version = parse_service_version(banner, port)
        vulns = check_vulnerability(service, version, banner)
        return port, service, version, vulns

    except (socket.error, ssl.SSLError, OSError):
        return None


def scan_tcp_ports(target, ports, connect_timeout=1, banner_timeout=3, max_workers=100):
    """Scan every port in *ports*, grab banners, and identify services.

    Returns a list of (port, service, version, vulns) tuples — only for
    ports that are open — sorted by port number.
    """
    results = []
    with tqdm.tqdm(total=len(ports), desc="Scanning TCP ports", unit="port") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_tcp_probe, target, port, connect_timeout, banner_timeout): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
                pbar.update(1)
    return sorted(results, key=lambda x: x[0])


def _udp_probe(target, port, timeout):
    """Send a service-specific (or empty) UDP packet; return port on reply."""
    probe = UDP_PROBES.get(port, b'')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(probe, (target, port))
        sock.recvfrom(1024)
        sock.close()
        return port
    except socket.timeout:
        return None
    except socket.error:
        return None


def scan_udp_ports(target, ports, timeout=2):
    """Probe well-known UDP service ports that fall within *ports*.

    Only ports listed in COMMON_UDP_SERVICES are tested — probing arbitrary
    UDP ports with generic payloads yields almost no useful signal.
    """
    known_ports = [p for p in ports if p in COMMON_UDP_SERVICES]
    open_ports = []
    if not known_ports:
        return open_ports
    with tqdm.tqdm(total=len(known_ports), desc="Scanning UDP ports", unit="port") as pbar:
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


# ── Service / version detection ──────────────────────────────────────────────

def parse_service_version(banner, port=None):
    """Return (service, version) from a banner string.

    Detection order matters — protocols that share the same opening bytes
    (SSH vs other, "220" FTP vs SMTP) are disambiguated by checking the most
    specific pattern first.
    """
    if not banner:
        return (PORT_SERVICE_HINTS.get(port, "unknown") if port else "unknown"), ""

    # ── SSH ──────────────────────────────────────────────────────────────────
    if banner.startswith("SSH-"):
        sw_field = banner.split()[0][4:]          # "2.0-OpenSSH_9.3p1"
        if '-' in sw_field:
            sw = sw_field.split('-', 1)[1]        # "OpenSSH_9.3p1"
            sw_lower = sw.lower()
            if sw_lower.startswith('openssh_'):
                return "ssh", "OpenSSH " + sw[8:]
            if sw_lower.startswith('dropbear_'):
                return "ssh", "Dropbear SSH " + sw[9:]
            if sw_lower.startswith('libssh_'):
                return "ssh", "libssh " + sw[7:]
            return "ssh", sw.replace('_', ' ')
        return "ssh", sw_field

    # ── IMAP — "* OK" prefix (must check before "220" FTP/SMTP) ─────────────
    if banner.startswith("* OK"):
        for pattern, fmt in [
            (r'Dovecot(?:\s+([\d.]+))?',  'Dovecot {}'),
            (r'Cyrus\s+IMAP\s+([\d.]+)',  'Cyrus IMAP {}'),
        ]:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                ver = m.group(1) or ""
                return "imap", fmt.format(ver).strip()
        return "imap", ""

    # ── POP3 ─────────────────────────────────────────────────────────────────
    if banner.startswith("+OK"):
        return PORT_SERVICE_HINTS.get(port, "mail"), ""

    # ── SMTP — port-disambiguated "220" (must check BEFORE generic FTP) ──────
    if banner.startswith("220") and port in (25, 465, 587, 2525):
        body = banner[4:].strip()
        for pattern, fmt in [
            (r'Postfix(?:\s+([\d.]+))?',            'Postfix {}'),
            (r'Exim\s+([\d.]+)',                    'Exim {}'),
            (r'Zimbra\s+([\d.]+)',                  'Zimbra {}'),
            (r'Sendmail\s+([\d.]+)',                'Sendmail {}'),
            (r'Microsoft\s+Exchange\s+Server',      'Microsoft Exchange Server'),
        ]:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                ver = (m.group(1) or "") if m.lastindex else ""
                return "mail", fmt.format(ver).strip()
        return "mail", body[:80]

    # ── FTP — any remaining "220" banner ─────────────────────────────────────
    if banner.startswith("220"):
        body = banner[4:].strip()
        for pattern, fmt in [
            (r'vsftpd\s+([\d.]+)',                      'vsftpd {}'),
            (r'ProFTPD\s+([\d.]+)',                     'ProFTPD {}'),
            (r'Pure-FTPd\s+([\d.]+)',                   'Pure-FTPd {}'),
            (r'Microsoft FTP Service(?:\s+([\d.]+))?',  'Microsoft IIS FTP Service {}'),
        ]:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                ver = (m.group(1) or "") if m.lastindex else ""
                return "ftp", fmt.format(ver).strip()
        return "ftp", body[:80]

    # ── HTTP — parse Server header ───────────────────────────────────────────
    if "HTTP/" in banner or re.search(r'\bServer:', banner, re.IGNORECASE):
        m = re.search(r'Server:\s*(.+?)(?:\r|\n|$)', banner, re.IGNORECASE)
        if m:
            server = m.group(1).strip()
            for pattern, fmt in [
                (r'Apache/(\d[\d.]+)',        'Apache httpd {}'),
                (r'nginx/(\d[\d.]+)',         'nginx {}'),
                (r'Microsoft-IIS/(\d[\d.]+)', 'Microsoft IIS {}'),
                (r'Apache Tomcat/(\d[\d.]+)', 'Apache Tomcat {}'),
            ]:
                vm = re.search(pattern, server, re.IGNORECASE)
                if vm:
                    return "http", fmt.format(vm.group(1))
            return "http", server[:80]
        return "http", ""

    # ── MySQL / MariaDB — binary greeting contains a plaintext version ───────
    if port == 3306:
        m = re.search(r'(\d+\.\d+\.\d+(?:-MariaDB|-[\w.]+)?)', banner)
        if m:
            ver = m.group(1)
            label = "MariaDB" if ("mariadb" in ver.lower() or "mariadb" in banner.lower()) else "MySQL"
            return "database", f"{label} {ver}"

    # ── Telnet ───────────────────────────────────────────────────────────────
    if port == 23:
        return "telnet", ""

    # ── Fall back to port-number hint ────────────────────────────────────────
    return (PORT_SERVICE_HINTS.get(port, "unknown") if port else "unknown"), ""


# ── Vulnerability lookup ─────────────────────────────────────────────────────

def check_vulnerability(service, version, banner=None):
    """Return a list of (cve, severity) tuples for the given service/version.

    Matching strategy (in order):
    1. Entries with an empty version string match all instances of the service.
    2. Exact case-insensitive match between parsed version and DB entry.
    3. Normalised substring search of the DB version string inside the raw banner.
    """
    if service not in vulnerable_services:
        return []

    results = []
    seen = set()

    for entry in vulnerable_services[service]:
        entry_version = entry.get("version", "")
        cve      = entry["cve"]
        severity = entry["severity"]

        if cve in seen:
            continue

        if not entry_version:                          # version-independent
            results.append((cve, severity))
            seen.add(cve)
            continue

        if version and entry_version.lower() == version.lower():
            results.append((cve, severity))
            seen.add(cve)
            continue

        if banner and entry_version:                   # fuzzy banner match
            norm_banner = re.sub(r'[_/]', ' ', banner.lower())
            norm_entry  = re.sub(r'[_/]', ' ', entry_version.lower())
            if norm_entry in norm_banner:
                results.append((cve, severity))
                seen.add(cve)

    return results


# ── Helpers ──────────────────────────────────────────────────────────────────

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
    """Parse a port spec into a deduplicated list of ints.

    Accepts: single port ``22``, range ``1-1024``, or mixed ``22,80,443,8000-8080``.
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
    return list(dict.fromkeys(ports))   # deduplicate, preserve order


def print_port_results(port, protocol, service, version, vulns):
    """Print a single port's findings to the terminal."""
    svc = service if service != "unknown" else "unknown service"
    ver = f" ({version})" if version else ""
    print(f"\n  [{protocol}/{port}]  {svc}{ver}")
    if vulns:
        for cve, severity in vulns:
            print(f"    {_color(cve, severity)}  |  Severity: {_color(severity, severity)}")
    else:
        print("    No known vulnerabilities")


def write_report(filepath, targets_data, ports, ports_str):
    """Write a Markdown vulnerability report.

    targets_data: list of dicts — one per target:
      { "target": str,
        "tcp_open": [(port, service, version, vulns), ...],
        "udp_open": [(port, service, vulns), ...] }
    """
    udp_probed = sorted(p for p in ports if p in COMMON_UDP_SERVICES)
    lines = [
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
        total_vulns = sum(len(r[3]) for r in tcp_open) + sum(len(r[2]) for r in udp_open)

        lines += [f"## Target: {target}", ""]

        # TCP
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

        # UDP
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

        # Summary
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


# ── Entry point ──────────────────────────────────────────────────────────────

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

        tcp_open    = scan_tcp_ports(target, ports)
        udp_results = scan_udp_ports(target, ports)

        udp_open = []
        for port in udp_results:
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
