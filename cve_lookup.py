import requests

def get_cve_info(cve_id):
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    headers = {
        "User-Agent": "Mozilla/5.0 (NetVulnScanner)"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        print(f"[DEBUG] {cve_id} → HTTP {response.status_code}")

        if response.status_code != 200:
            return None

        data = response.json()

        # Extract info
        description = data.get("summary", "No description available.")
        cvss_score = data.get("cvss", "Unknown")

        # Convert score to rough severity
        if isinstance(cvss_score, (int, float)):
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0:
                severity = "LOW"
            else:
                severity = "NONE"
        else:
            severity = "Unknown"

        return {
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score
        }

    except Exception as e:
        print(f"[!] CIRCL lookup failed for {cve_id}: {e}")
        return None
