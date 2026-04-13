# Network Analyzer

A Python-based network vulnerability scanner that identifies open TCP and UDP ports, detects running services and versions via banner grabbing, and checks them against a database of 238 known CVEs. Results are printed to the terminal and saved as a Markdown report.

---

## Features

- **TCP Port Scanning** — threaded `connect()` scan across any port range; up to 100 concurrent probes
- **UDP Port Scanning** — probes well-known service ports (DNS, NTP, SNMP, SIP, and more) with service-specific payloads
- **Banner Grabbing** — connects to each open TCP port and reads the service banner; sends an HTTP HEAD request for web ports to retrieve the `Server` header
- **TLS/SSL Support** — automatically upgrades to TLS for encrypted ports (443, 465, 636, 993, 995, 8443) before reading
- **Service Detection** — identifies SSH, FTP, SMTP/Mail, HTTP/HTTPS, IMAP, POP3, MySQL/MariaDB, Telnet, and more from banner content; falls back to port-number hints for protocols that do not advertise a banner
- **Vulnerability Checking** — matches detected service versions against 238 CVEs across 17 service categories; reports CVE ID and severity (Critical / High / Medium / Low), or `No known vulnerabilities`
- **Flexible Port Input** — single port, range, or comma-separated mix
- **CIDR Range Scanning** — scans every host in a subnet in a single run
- **Markdown Report** — structured `.md` file with per-target results, open port details, vulnerability status, and a summary table

---

## Requirements

- Python 3.6+
- `tqdm` — progress bars

```bash
pip install -r requirements.txt
```

Root privileges are required on Linux/macOS for raw socket operations used by UDP scanning.

---

## Installation

```bash
git clone https://github.com/casto-tech/network_analyzer.git
cd network_analyzer
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

```
sudo venv/bin/python3 network-analyzer.py <target> [ports] [output_file]
```

| Argument | Required | Default | Description |
|---|---|---|---|
| `target` | Yes | — | IP address, hostname, or CIDR range |
| `ports` | No | `1-1024` | Port specification (see formats below) |
| `output_file` | No | `scan_results.md` | Path for the Markdown report |

### Port Formats

| Format | Example | Description |
|---|---|---|
| Single port | `22` | One port |
| Range | `1-1024` | All ports from 1 to 1024 inclusive |
| Comma-separated | `22,80,443` | Specific ports |
| Mixed | `22,80,443,8000-8080` | Combination of the above |

---

## Examples

### Scan a single port

```bash
sudo venv/bin/python3 network-analyzer.py 192.168.1.1 22
```

Checks only port 22. Useful for quickly checking whether SSH is running and whether the detected version has known CVEs.

---

### Scan common web ports

```bash
sudo venv/bin/python3 network-analyzer.py 192.168.1.1 80,443,8080,8443
```

Grabs HTTP/HTTPS banners from all four ports in parallel. TLS is handled automatically on 443 and 8443.

---

### Scan a port range

```bash
sudo venv/bin/python3 network-analyzer.py 192.168.1.1 1-1024
```

Scans the first 1024 ports — equivalent to an nmap default scan. Results default to `scan_results.md`.

---

### Scan all 65535 ports

```bash
sudo venv/bin/python3 network-analyzer.py 192.168.1.1 1-65535
```

Full port sweep. Slower but reveals non-standard service ports.

---

### Scan specific mixed ports

```bash
sudo venv/bin/python3 network-analyzer.py 192.168.1.1 22,80,443,3306,3389,8000-8090
```

Combines individual ports and ranges in one argument.

---

### Scan a hostname

```bash
sudo venv/bin/python3 network-analyzer.py example.com 1-1024
```

Resolves the hostname and scans it. The resolved IP appears in the report.

---

### Scan a CIDR subnet

```bash
sudo venv/bin/python3 network-analyzer.py 192.168.1.0/24 22,80,443
```

Scans every host in the `/24` subnet (254 hosts) for ports 22, 80, and 443. Each host gets its own section in the report.

---

### Save report to a custom file

```bash
sudo venv/bin/python3 network-analyzer.py 10.0.0.1 1-1024 /home/user/reports/office_scan.md
```

Writes the Markdown report to the specified path instead of `scan_results.md`.

---

### Scan only UDP service ports

```bash
sudo venv/bin/python3 network-analyzer.py 192.168.1.1 53,123,161,500,5060
```

Any ports in the request that match well-known UDP services are probed with service-specific payloads (DNS query, NTP client request, etc.). TCP and UDP scanning always run together — ports that are in both the request and the UDP service list get probed on both protocols.

---

## Terminal Output

```
Scanning target: 192.168.1.10

Scanning TCP ports: 100%|████████████████| 1000/1000 [00:08<00:00, 123.4port/s]
Scanning UDP ports: 100%|█████████████████████| 5/5 [00:02<00:00,  2.3port/s]

Results for 192.168.1.10:

  [TCP/22]  ssh (OpenSSH 9.3p1)
    CVE-2023-38408  |  Severity: Critical

  [TCP/80]  http (Apache httpd 2.4.49)
    CVE-2021-41773  |  Severity: Critical

  [TCP/443]  http (nginx 1.23.0)
    No known vulnerabilities

  [TCP/3306]  database (MySQL 8.0.27)
    No known vulnerabilities

  [UDP/53]  dns
    No known vulnerabilities

Scan complete. Results saved to scan_results.md
```

Severity labels are colour-coded in the terminal:

| Severity | Colour |
|---|---|
| Critical | Red |
| High | Yellow |
| Medium | Blue |
| Low | Cyan |

---

## Report Format

Each scan produces a `scan_results.md` file structured as follows:

```markdown
# Network Vulnerability Scan Report

**Scan Date:** 2026-04-12 15:30:22
**TCP Ports:** 1-1024 (1024 ports scanned)
**UDP Ports:** 53, 123, 161, 500, 5060

---

## Target: 192.168.1.10

### TCP Ports

**Port 22** | OPEN | Service: `ssh` — `OpenSSH 9.3p1`
**Status: VULNERABLE**
- CVE-2023-38408 | Severity: **Critical**

**Port 80** | OPEN | Service: `http` — `Apache httpd 2.4.49`
**Status: VULNERABLE**
- CVE-2021-41773 | Severity: **Critical**

**Port 443** | OPEN | Service: `http` — `nginx 1.23.0`
**Status: No known vulnerabilities**

*Closed TCP ports: 1021*

### UDP Ports

No UDP service ports responded.

### Summary

| | |
|---|---|
| Open TCP ports | 3 |
| Open UDP ports | 0 |
| Vulnerabilities | **2 found** |
```

---

## Supported Services

| Service | Detected Via | Examples |
|---|---|---|
| SSH | Banner (`SSH-2.0-...`) | OpenSSH, Dropbear, libssh |
| FTP | Banner (`220 ...`) | vsftpd, ProFTPD, Pure-FTPd, IIS FTP |
| SMTP / Mail | Banner (`220 ...` on port 25/465/587) | Postfix, Exim, Zimbra, Exchange |
| HTTP / HTTPS | `Server:` header (HEAD request sent) | Apache, nginx, IIS, Tomcat |
| IMAP | Banner (`* OK ...`) | Dovecot, Cyrus IMAP |
| POP3 | Banner (`+OK ...`) | Any POP3 server |
| MySQL / MariaDB | Binary greeting on port 3306 | MySQL, MariaDB |
| Telnet | Port 23 hint | Any |
| DNS | Port 53 hint + UDP probe | BIND, Unbound, PowerDNS, dnsmasq |
| SNMP | Port 161 hint | Net-SNMP |
| NTP | Port 123 hint + UDP probe | NTP, chrony |
| SIP | Port 5060 hint | Asterisk, Kamailio, FreeSWITCH |
| SMB | Port 445 hint | Windows SMB, Samba |
| RDP | Port 3389 hint | Windows RDP |
| LDAP | Port 389/636 hint | OpenLDAP, Active Directory |
| Database | Port hint (1433/1521/3306/5432/6379/27017) | MSSQL, Oracle, PostgreSQL, Redis, MongoDB |
| VPN | Port 1194 hint | OpenVPN, FortiOS, PAN-OS, Cisco ASA |
| Kerberos | Port 88 hint | Windows Kerberos, Heimdal |
| RPC | Port 135 hint | Windows RPC, rpcbind |

---

## Vulnerability Database

CVE data lives in `vulnerabilities.json` alongside the script. It currently covers **238 CVEs** across 17 service categories, focused on Critical and High severity findings from 2015–2025.

| Category | CVEs |
|---|---|
| HTTP / Web Applications | 89 |
| Mail (SMTP / Exchange / Exim / Zimbra) | 21 |
| VPN (FortiOS, PAN-OS, Cisco, Juniper, Pulse) | 23 |
| SSH | 11 |
| SMB / Windows | 13 |
| DNS | 13 |
| Database (MySQL, PostgreSQL, Redis, MSSQL, Oracle, MongoDB) | 20 |
| RDP | 7 |
| FTP | 7 |
| Kerberos | 6 |
| SIP | 6 |
| IMAP | 5 |
| LDAP | 5 |
| NTP | 4 |
| RPC | 4 |
| SNMP | 3 |
| Telnet | 1 |

To add new CVEs, append entries to the relevant array in `vulnerabilities.json`:

```json
{
  "version": "nginx 1.25.0",
  "cve": "CVE-2024-XXXXX",
  "severity": "Critical"
}
```

Valid severity values: `Critical`, `High`, `Medium`, `Low`.

---

## Limitations

- **UDP detection is conservative** — only the ~20 ports in `COMMON_UDP_SERVICES` are probed. Services on non-standard UDP ports will not be found.
- **Version matching requires a banner** — protocols that do not advertise a version string (SMB, RDP, Kerberos, most databases) are identified by port number only; version-specific CVEs will not match unless the banner contains the version.
- **No OS fingerprinting** — the tool does not attempt to identify the underlying operating system.
- **No stealth scanning** — uses full TCP connect, which is logged by firewalls and IDS systems.
