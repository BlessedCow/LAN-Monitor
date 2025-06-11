import requests
import csv

# In-memory cache for NVD service lookups
_nvd_cache = {}

# Common port-to-service name mapping
PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 3389: "rdp", 5900: "vnc"
}

def query_nvd(service, max_results=3):
    
    # Query NVD for CVEs matching the service keyword.
    # Returns cached result if available.
    
    if service in _nvd_cache:
        return _nvd_cache[service]

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": service, "resultsPerPage": max_results}
    try:
        r = requests.get(url, params=params, timeout=5)
        r.raise_for_status()
        data = r.json()

        results = []
        for cve in data.get("vulnerabilities", []):
            item = cve.get("cve", {})
            cve_id = item.get("id", "N/A")
            description = item.get("descriptions", [{}])[0].get("value", "No description available.")
            published = item.get("published", "N/A")
            cvss = "N/A"

            # Check for CVSS score across v3.1, v3.0, v2
            metrics = item.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    data = entries[0].get("cvssData") or entries[0]
                    cvss = data.get("baseScore") or data.get("score") or "N/A"
                    break

            results.append({
                "cve_id": cve_id,
                "description": description,
                "cvss": cvss,
                "published": published
            })

        _nvd_cache[service] = results
        return results

    except Exception as e:
        return [{
            "cve_id": "Error",
            "description": str(e),
            "cvss": "N/A",
            "published": "N/A"
        }]

def load_cisa_kev():
    # Load CISA Exploited Vulnerabilities list.
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv"
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        decoded = r.content.decode("utf-8").splitlines()
        reader = csv.DictReader(decoded)
        return {row["cveID"].strip().upper(): row for row in reader}
    except Exception:
        return {}
