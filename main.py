from scanner import run_nmap_scan
from exploit_mapper import search_exploits
from report_generator import generate_report

def build_scan_results(ip_range):
    print(f"[+] Scanning network: {ip_range}")
    scan_data = run_nmap_scan(ip_range)

    structured_results = []
    for entry in scan_data:
        print(f"[*] Scanning {entry['host']}:{entry['port']} - {entry['service']} {entry['version']}")
        vulns = search_exploits(entry['service'], entry['version'])

        structured_results.append({
            "host": entry['host'],
            "port": entry['port'],
            "service": entry['service'],
            "version": entry['version'],
            "vulnerabilities": vulns
        })

    return structured_results

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 main.py <target-ip-or-range>")
        print("Example: python3 main.py 192.168.1.0/24")
        exit(1)

    target = sys.argv[1]

    print("=" * 50)
    print("NetVulnScanner - Network Vulnerability Scanner")
    print("=" * 50)

    results = build_scan_results(target)
    generate_report(results, style="detailed")
