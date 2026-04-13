import socket
import json
import sys
import os
import re
import ssl
import ctypes
import ipaddress
import concurrent.futures
import platform
import subprocess
import ftplib
import urllib.request
import base64
import argparse
from datetime import datetime

import tqdm

# Try to load Scapy for our Stealth Scan. If not installed, we gracefully disable the feature.
try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Suppress IPv6 warnings
    from scapy.all import sr, IP, TCP, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Check if running as root/admin
is_admin = False
if sys.platform.startswith('win'):
    if ctypes.windll.shell32.IsUserAnAdmin():
        is_admin = True
    else:
        print("Warning: This script requires administrative privileges for full functionality (especially Stealth Scanning).")
else:
    if os.geteuid() == 0:
        is_admin = True
    else:
        print("Warning: This script requires root privileges for full functionality (especially Stealth Scanning).")

# Load vulnerabilities from the JSON file next to this script
VULN_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vulnerabilities.json')
try:
    with open(VULN_DB_PATH, 'r') as f:
        vulnerable_services = json.load(f)
except FileNotFoundError:
    print(f"Error: vulnerabilities.json not found at {VULN_DB_PATH}. Exiting.")
    sys.exit(1)

# ── Port / service mappings ──────────────────────────────────────────────────

TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 993, 995, 3269, 5061, 8443}

HTTP_PORTS = {
    80, 443,            
    3000, 5000, 5173,   
    8000, 8008, 8080,   
    8081, 8443, 8888,   
    9000, 9090          
}

COMMON_UDP_SERVICES = {
    19: "chargen", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp",
    162: "snmptrap", 177: "xdmcp", 500: "isakmp", 520: "rip",
    631: "ipp", 646: "ldp", 1434: "ms-sql-m", 1900: "ssdp",
    5060: "sip", 5353: "mdns", 5355: "llmnr",
}

UDP_PROBES = {
    53: (
        b'\xaa\xbb'              
        b'\x01\x00'              
        b'\x00\x01'              
        b'\x00\x00\x00\x00\x00\x00'  
        b'\x07version\x04bind\x00'
        b'\x00\x10'              
        b'\x00\x03'              
    ),
    123: bytes([0x1b] + [0] * 47),
}

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

# ── Host Discovery (Ping Sweep) ──────────────────────────────────────────────

def is_host_alive(target):
    """Pings a single target to see if it is online."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    
    try:
        output = subprocess.run(
            ['ping', param, '1', timeout_param, timeout_val, target], 
            capture_output=True, text=True
        )
        if output.returncode == 0:
            return target
    except Exception:
        pass
    return None

def discover_alive_hosts(targets):
    """Takes a list of IPs and returns only the ones that reply to ping."""
    if len(targets) == 1:
        return targets 

    alive_hosts = []
    print(f"\nPerforming ping sweep on {len(targets)} hosts to find active devices...")
    
    with tqdm.tqdm(total=len(targets), desc="Discovering alive hosts", unit="host") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(is_host_alive, t): t for t in targets}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)
                pbar.update(1)
                
    return alive_hosts

# ── Active Misconfiguration Checks ───────────────────────────────────────────

def check_anonymous_ftp(target, port):
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=3)
        ftp.login('anonymous', 'anonymous@example.com')
        ftp.quit()
        return True
    except Exception:
        return False

def check_open_redis(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        s.sendall(b"PING\r\n")
        data = s.recv(1024)
        s.close()
        if b"+PONG" in data:
            return True
    except Exception:
        pass
    return False

def check_tomcat_default_login(target, port):
    try:
        url = f"http://{target}:{port}/manager/html"
        req = urllib.request.Request(url)
        auth = base64.b64encode(b'tomcat:tomcat').decode('ascii')
        req.add_header('Authorization', f'Basic {auth}')
        
        resp = urllib.request.urlopen(req, timeout=3)
        if resp.status == 200:
            return True
    except Exception:
        pass
    return False

# ── OS Fingerprinting ────────────────────────────────────────────────────────

def detect_os(target, tcp_open_results):
    os_guesses = []

    for _, _, version, _ in tcp_open_results:
        if not version:
            continue
        v_lower = version.lower()
        if any(x in v_lower for x in ['ubuntu', 'debian', 'centos', 'linux', 'red hat']):
            os_guesses.append("Linux (Banner Hint)")
        elif any(x in v_lower for x in ['windows', 'iis', 'win32']):
            os_guesses.append("Windows (Banner Hint)")
        elif 'freebsd' in v_lower:
            os_guesses.append("FreeBSD (Banner Hint)")

    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        output = subprocess.run(['ping', param, '1', target], capture_output=True, text=True, timeout=2).stdout
        
        ttl_match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                os_guesses.append("Linux/macOS (TTL)")
            elif ttl <= 128:
                os_guesses.append("Windows (TTL)")
            else:
                os_guesses.append("Network Device/Solaris (TTL)")
    except Exception:
        pass 

    if not os_guesses:
        return "Unknown"

    unique_guesses = list(dict.fromkeys(os_guesses))
    return " / ".join(unique_guesses)

# ── Scanning ─────────────────────────────────────────────────────────────────

def scapy_syn_scan(target, ports, timeout=2.0):
    """Perform a batch TCP SYN scan using Scapy for stealth."""
    open_ports = []
    print(f"  [*] Running Scapy Stealth SYN scan on {len(ports)} ports...")
    
    # Scapy's sr() function can take an entire array of ports and test them in bulk!
    ans, unans = sr(IP(dst=target)/TCP(dport=ports, flags="S"), timeout=timeout, verbose=0)
    
    for sent, received in ans:
        if received.haslayer(TCP):
            if received[TCP].flags == 0x12: # 0x12 means SYN-ACK
                port = sent[TCP].dport
                open_ports.append(port)
                # Be stealthy: Send a RST (Reset) back immediately to tear down the half-open connection
                send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
                
    return sorted(open_ports)


def _tcp_probe(target, port, connect_timeout, banner_timeout):
    """Open one TCP connection, grab the banner, and return scan results."""
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(connect_timeout)
        if raw_sock.connect_ex((target, port)) != 0:
            raw_sock.close()
            return None

        raw_sock.settimeout(banner_timeout)

        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(raw_sock, server_hostname=target)
            except ssl.SSLError:
                sock = raw_sock          
        else:
            sock = raw_sock

        if port in HTTP_PORTS:
            try:
                sock.sendall(
                    b"HEAD / HTTP/1.0\r\n"
                    b"Host: " + target.encode() + b"\r\n"
                    b"User-Agent: NetworkAnalyzer/1.0\r\n\r\n"
                )
            except (socket.error, ssl.SSLError):
                pass

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
    """Scan every port in *ports*, grab banners, and identify services."""
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
    """Probe well-known UDP service ports that fall within *ports*."""
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
    if not banner:
        return (PORT_SERVICE_HINTS.get(port, "unknown") if port else "unknown"), ""

    if banner.startswith("SSH-"):
        sw_field = banner.split()[0][4:]          
        if '-' in sw_field:
            sw = sw_field.split('-', 1)[1]        
            sw_lower = sw.lower()
            if sw_lower.startswith('openssh_'):
                return "ssh", "OpenSSH " + sw[8:]
            if sw_lower.startswith('dropbear_'):
                return "ssh", "Dropbear SSH " + sw[9:]
            if sw_lower.startswith('libssh_'):
                return "ssh", "libssh " + sw[7:]
            return "ssh", sw.replace('_', ' ')
        return "ssh", sw_field

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

    if banner.startswith("+OK"):
        return PORT_SERVICE_HINTS.get(port, "mail"), ""

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

    if port == 3306:
        m = re.search(r'(\d+\.\d+\.\d+(?:-MariaDB|-[\w.]+)?)', banner)
        if m:
            ver = m.group(1)
            label = "MariaDB" if ("mariadb" in ver.lower() or "mariadb" in banner.lower()) else "MySQL"
            return "database", f"{label} {ver}"

    if port == 23:
        return "telnet", ""

    return (PORT_SERVICE_HINTS.get(port, "unknown") if port else "unknown"), ""

# ── Vulnerability lookup ─────────────────────────────────────────────────────

def check_vulnerability(service, version, banner=None):
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

        if not entry_version:                          
            results.append((cve, severity))
            seen.add(cve)
            continue

        if version and entry_version.lower() == version.lower():
            results.append((cve, severity))
            seen.add(cve)
            continue

        if banner and entry_version:                   
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
    ports = []
    try:
        for part in ports_str.split(','):
            part = part.strip()
            if not part: continue
            if '-' in part:
                parts_split = part.split('-', 1)
                if not parts_split[0] or not parts_split[1]:
                    raise ValueError(f"Invalid port range format: {part}")
                start, end = map(int, parts_split)
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
    return list(dict.fromkeys(ports))   

def print_port_results(port, protocol, service, version, vulns):
    svc = service if service != "unknown" else "unknown service"
    ver = f" ({version})" if version else ""
    print(f"\n  [{protocol}/{port}]  {svc}{ver}")
    if vulns:
        for cve, severity in vulns:
            print(f"    {_color(cve, severity)}  |  Severity: {_color(severity, severity)}")
    else:
        print("    No known vulnerabilities")

def write_report(filepath, targets_data, ports, ports_str):
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
        os_guess    = entry.get("os_guess", "Unknown")
        tcp_closed  = len(ports) - len(tcp_open)
        total_vulns = sum(len(r[3]) for r in tcp_open) + sum(len(r[2]) for r in udp_open)

        lines += [
            f"## Target: {target}", 
            f"**Detected OS:** {os_guess}",
            ""
        ]

        lines += ["### TCP Ports", ""]
        if tcp_open:
            for port, service, version, vulns in sorted(tcp_open, key=lambda x: x[0]):
                ver_str = f" — `{version}`" if version else ""
                lines.append(f"**Port {port}** | OPEN | Service: `{service}`{ver_str}  ")
                if vulns:
                    lines.append("**Status: VULNERABLE** ")
                    for cve, severity in vulns:
                        lines.append(f"- {cve} | Severity: **{severity}**")
                else:
                    lines.append("**Status: No known vulnerabilities**")
                lines.append("")
        else:
            lines += ["No open TCP ports found.", ""]
        lines += [f"*Closed TCP ports: {tcp_closed}*", ""]

        lines += ["### UDP Ports", ""]
        if udp_open:
            for port, service, vulns in sorted(udp_open, key=lambda x: x[0]):
                lines.append(f"**Port {port}** | OPEN | Service: `{service}`  ")
                if vulns:
                    lines.append("**Status: VULNERABLE** ")
                    for cve, severity in vulns:
                        lines.append(f"- {cve} | Severity: **{severity}**")
                else:
                    lines.append("**Status: No known vulnerabilities**")
                lines.append("")
        else:
            lines += ["No UDP service ports responded.", ""]

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
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("target", help="IP address, hostname, or CIDR range")
    parser.add_argument("ports", nargs="?", default="1-1024", help="Ports to scan (single, range, or comma-separated)")
    parser.add_argument("-o", "--output", default="scan_results.md", help="Path for the Markdown report")
    parser.add_argument("-j", "--json", action="store_true", help="Also output results to a JSON file")
    parser.add_argument("-A", "--active", action="store_true", help="Enable active checks (FTP, Redis, Tomcat)")
    parser.add_argument("-Pn", "--skip-ping", action="store_true", help="Skip ping sweep host discovery")
    parser.add_argument("-sS", "--stealth", action="store_true", help="Perform Stealth SYN Scan (No Banners, requires admin & Scapy)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="TCP connection timeout in seconds (default: 1.0)")

    args = parser.parse_args()

    ports = parse_ports(args.ports)

    # Validate Stealth Mode Dependencies
    if args.stealth:
        if not SCAPY_AVAILABLE:
            print("\n[!] Error: You requested a Stealth Scan (-sS), but 'scapy' is not installed.")
            print("    Please run 'pip install scapy' and try again.\n")
            sys.exit(1)
        if not is_admin:
            print("\n[!] Error: Stealth Scanning requires root/administrator privileges.")
            print("    Please run the script with 'sudo' or from an Admin prompt.\n")
            sys.exit(1)

    try:
        network = ipaddress.ip_network(args.target, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    except ValueError:
        if not validate_target(args.target):
            print("Error: Invalid target IP or hostname.")
            sys.exit(1)
        targets = [args.target]

    if args.skip_ping:
        alive_targets = targets
    else:
        alive_targets = discover_alive_hosts(targets)
        
    if not alive_targets:
        print("\nNo alive hosts found to scan. Exiting.")
        sys.exit(0)

    targets_data = []

    for target in alive_targets:
        print(f"\nScanning target: {target}")

        # Choose the scan type based on the user's flags
        if args.stealth:
            open_ports = scapy_syn_scan(target, ports, timeout=args.timeout)
            tcp_open = []
            for p in open_ports:
                # We can't grab banners in stealth mode, so we rely entirely on port hints
                service_guess = PORT_SERVICE_HINTS.get(p, "unknown")
                vulns = check_vulnerability(service_guess, "", None)
                tcp_open.append((p, service_guess, "Stealth Mode (No Banner)", vulns))
        else:
            tcp_open = scan_tcp_ports(target, ports, connect_timeout=args.timeout, max_workers=args.threads)
        
        udp_results = scan_udp_ports(target, ports, timeout=max(2.0, args.timeout))
        
        os_guess = detect_os(target, tcp_open)

        # ── Run Active Checks on Discovered Ports (If Enabled) ──
        if args.active and not args.stealth:
            for row in tcp_open:
                port = row[0]
                service = row[1]
                vulns = row[3]
                
                if service == "ftp":
                    if check_anonymous_ftp(target, port):
                        vulns.append(("Anonymous FTP Login Allowed", "High"))
                        
                elif service == "database" or port == 6379:
                    if check_open_redis(target, port):
                        vulns.append(("Unauthenticated Redis Database", "Critical"))
                        
                elif service == "http":
                    if check_tomcat_default_login(target, port):
                        vulns.append(("Tomcat Default Credentials (tomcat:tomcat)", "Critical"))
        elif args.active and args.stealth:
            print("  [!] Notice: Active misconfiguration checks (-A) bypassed to maintain stealth.")

        udp_open = []
        for port in udp_results:
            service = COMMON_UDP_SERVICES.get(port, "unknown")
            vulns   = check_vulnerability(service, "", None)
            udp_open.append((port, service, vulns))

        print(f"\nResults for {target} (Detected OS: {os_guess}):")
        for port, service, version, vulns in tcp_open:
            print_port_results(port, "TCP", service, version, vulns)
        for port, service, vulns in udp_open:
            print_port_results(port, "UDP", service, "", vulns)

        targets_data.append({
            "target": target, 
            "tcp_open": tcp_open, 
            "udp_open": udp_open,
            "os_guess": os_guess
        })

    # Write Markdown Report
    write_report(args.output, targets_data, ports, args.ports)
    print(f"\nScan complete. Results saved to {args.output}")

    # Write JSON Report if requested
    if args.json:
        json_file = os.path.splitext(args.output)[0] + ".json"
        
        json_friendly_data = []
        for d in targets_data:
            json_friendly_data.append({
                "target": d["target"],
                "os_guess": d["os_guess"],
                "tcp_open": [{"port": r[0], "service": r[1], "version": r[2], "vulns": [{"cve": v[0], "severity": v[1]} for v in r[3]]} for r in d["tcp_open"]],
                "udp_open": [{"port": r[0], "service": r[1], "vulns": [{"cve": v[0], "severity": v[1]} for v in r[2]]} for r in d["udp_open"]]
            })
            
        with open(json_file, 'w') as f:
            json.dump(json_friendly_data, f, indent=4)
        print(f"JSON results saved to {json_file}")