# Network Analyzer

A standalone Python-based network scanning tool designed to identify open TCP and UDP ports, detect services, and check for known vulnerabilities without relying on external tools like `nmap`.

## Features

- **Port Scanning**: Scans TCP and UDP ports using custom logic with the `scapy` library.
- **Service Detection**: Identifies services on TCP ports via banner grabbing; assumes services on UDP ports based on common assignments.
- **Vulnerability Checking**: Matches detected services against a JSON database of known vulnerabilities.
- **Progress Tracking**: Displays a real-time progress bar during scans.
- **Output**: Saves results in a CSV-like text file for easy analysis.

## Requirements

- Python 3.6+
- `scapy` (for packet manipulation)
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
sudo python network_analyzer.py <target> [ports] [output_file]
```
