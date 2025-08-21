import nmap

def run_nmap_scan(ip_range):
    nm = nmap.PortScanner()
    results = []

    print(f"[+] Running Nmap scan on: {ip_range}")
    nm.scan(hosts=ip_range, arguments='-sV -T4')

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port].get('name', '')
                version = nm[host][proto][port].get('version', '')
                results.append({
                    'host': host,
                    'port': port,
                    'service': service,
                    'version': version
                })

    return results
