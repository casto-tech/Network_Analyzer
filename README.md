# Network Analyzer

A standalone Python-based network scanning tool designed to identify open TCP and UDP ports, detect services, and check for known vulnerabilities without relying on external tools like `nmap`.

## Features

- **Port Scanning**: Scans TCP and UDP ports using custom logic with the `scapy` library.
- **Service Detection**: Identifies services on TCP ports via banner grabbing (SSH, HTTP, FTP, SMTP, and more); assumes services on UDP ports based on common port assignments.
- **Vulnerability Checking**: Matches detected services and versions against a JSON database of known CVEs. Reports CVE number and severity (Critical / High / Medium / Low), or prints **"No known vulnerabilities"** when nothing matches.
- **Progress Tracking**: Displays a real-time progress bar during scans.
- **Flexible Port Input**: Accepts a single port (`22`), a range (`1-1024`), or comma-separated values (`22,80,443,8000-8080`).
- **Output**: Prints results to the terminal and saves them to a CSV file for further analysis.

## Requirements

- Python 3.6+
- `tqdm` (for progress bar)

## Installation

1. **Clone the Repository**:
 ```bash
   git clone https://github.com/casto-tech/network_analyzer.git
   cd network_analyzer 
 ```

2. **Install Dependencies**:

```bash
pip install -r requirements.txt
```

Ensure Root Privileges: The tool requires root privileges for raw socket operations (e.g., on Linux, use sudo).

3. **Usage**:
Run the script with the following command

```bash
sudo python network-analyzer.py <target> [ports] [output_file]
```

| Argument | Required | Description |
|---|---|---|
| `target` | Yes | Hostname, IP address, or CIDR range (e.g. `192.168.1.0/24`) |
| `ports` | No | Single port, range, or comma-separated list. Defaults to `1-1024` |
| `output_file` | No | Path for Markdown output. Defaults to `scan_results.md` |

**Examples**

```bash
# Scan a single port
sudo python network-analyzer.py 192.168.1.1 22

# Scan specific ports
sudo python network-analyzer.py example.com 22,80,443

# Scan a port range
sudo python network-analyzer.py 10.0.0.1 1-1024 results.txt
```

**Sample output**

```
Scanning target: 192.168.1.1

Results for 192.168.1.1:

  [TCP/22]  ssh (OpenSSH 9.3p1)
    CVE-2023-38408  |  Severity: Critical

  [TCP/80]  http (Apache httpd 2.4.49)
    CVE-2021-41773  |  Severity: Critical

  [TCP/443]  http (nginx 1.23.0)
    No known vulnerabilities
```
