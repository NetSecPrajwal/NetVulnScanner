# NetVulnScanner 🔍
A Python-based network vulnerability scanner that detects open ports, matches known exploits, and enriches vulnerabilities with CVE data using the CIRCL API.

## Features
- 🔍 Nmap-based network and service scanning
- 💣 Exploit lookup via Exploit-DB (`searchsploit`)
- 📎 CVE enrichment using CIRCL CVE API (no API key required)
- 📄 Clean, human-readable report output in `.txt` format
- 🧠 Smart CVE mapping for common exploits (vsftpd, Samba, rpcbind, etc.)

## Usage

```bash
# Scan a single IP or CIDR range
python3 main.py 192.168.1.0/24
```

Results are saved in the `reports/` folder with timestamped filenames.

## Installation

```bash
git clone https://github.com/yourusername/NetVulnScanner.git
cd NetVulnScanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Requirements
- Python 3.x
- Nmap
- searchsploit (`exploitdb` package)

Install searchsploit (if not already available):

```bash
sudo apt install exploitdb
```

## Disclaimer
This tool is for educational and authorized penetration testing only. Use responsibly.
