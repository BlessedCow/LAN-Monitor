# scripts/update_vuln_data.py
import os
import sqlite3
import requests
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

# ---------- Config ----------
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "vulns.db"

NVD_API_KEY = os.getenv("NVD_API_KEY")
print("[*] NVD_API_KEY loaded:", bool(NVD_API_KEY))

NVD_CVES_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

HEADERS = {
    "User-Agent": "LAN-Monitor/1.0",
    "Accept": "application/json",
}
if NVD_API_KEY:
    # NVD API 2.0 uses this header name
    HEADERS["apiKey"] = NVD_API_KEY

# crude keyword mapping (offline “service guess”)
SERVICE_KEYWORDS = {
    "ssh": ["ssh", "openssh"],
    "rdp": ["rdp", "remote desktop", "terminal services"],
    "smb": ["smb", "samba", "cifs", "netlogon"],
    "http": ["http", "apache", "nginx", "iis", "tomcat"],
    "https": ["https", "tls", "ssl", "apache", "nginx", "iis", "tomcat"],
    "dns": ["dns", "bind", "named"],
    "snmp": ["snmp"],
    "ftp": ["ftp"],
    "smtp": ["smtp", "postfix", "exim", "sendmail"],
    "imap": ["imap", "dovecot"],
    "pop3": ["pop3", "dovecot"],
    "telnet": ["telnet"],
    "mysql": ["mysql", "mariadb"],
    "postgres": ["postgres", "postgresql"],
    "vnc": ["vnc"],
    "redis": ["redis"],
}

# ---------- DB ----------
def create_db():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                service TEXT,
                description TEXT,
                score REAL,
                published TEXT,
                is_exploited INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_cpes (
                cve_id TEXT NOT NULL,
                cpe TEXT NOT NULL,
                PRIMARY KEY (cve_id, cpe)
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_services ON cves(service)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_cpes_cpe ON cve_cpes(cpe)")
        conn.commit()

def upsert_rows(rows):
    if not rows:
        return
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.executemany("""
            INSERT OR REPLACE INTO cves
            (cve_id, service, description, score, published, is_exploited)
            VALUES (?, ?, ?, ?, ?, ?)
        """, rows)
        conn.commit()

# ---------- Helpers ----------
def load_cisa_kev_set() -> set[str]:
    print("[*] Downloading CISA KEV (JSON)...")
    r = requests.get(CISA_KEV_JSON, headers=HEADERS, timeout=60)
    r.raise_for_status()
    data = r.json()
    kev = set()
    for item in data.get("vulnerabilities", []):
        cve = (item.get("cveID") or "").strip().upper()
        if cve:
            kev.add(cve)
    return kev

def guess_service(desc: str) -> str | None:
    d = (desc or "").lower()
    for svc, kws in SERVICE_KEYWORDS.items():
        for kw in kws:
            if kw in d:
                return svc
    return None

def extract_cpes_from_cve(cve_obj: dict) -> set[str]:
    cpes = set()

    def walk(node):
        if isinstance(node, dict):
            if "cpeMatch" in node and isinstance(node["cpeMatch"], list):
                for m in node["cpeMatch"]:
                    if not isinstance(m, dict):
                        continue
                    criteria = m.get("criteria")
                    vulnerable = m.get("vulnerable")
                    if criteria and (vulnerable is True or vulnerable is None):
                        cpes.add(criteria)

            for v in node.values():
                walk(v)

        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(cve_obj.get("configurations") or cve_obj)
    return cpes
    
def walk(node):
    if isinstance(node, dict):
        if "cpeMatch" in node and isinstance(node["cpeMatch"], list):
            for m in node["cpeMatch"]:
                if not isinstance(m, dict):
                    continue
                criteria = m.get("criteria")
                vulnerable = m.get("vulnerable")
                if criteria and (vulnerable is True or vulnerable is None):
                    cpe_set.add(criteria)
        for v in node.values():
            walk(v)
    elif isinstance(node, list):
        for v in node:
            walk(v)
    
    walk(cve_obj.get("configurations") or cve_obj)
    return cpes


def upsert_cpe_rows(cpe_rows):
    if not cpe_rows:
        return
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.executemany("""
            INSERT OR REPLACE INTO cve_cpes (cve_id, cpe)
            VALUES (?, ?)
        """, cpe_rows)
        conn.commit()

def pick_cvss_score(metrics: dict) -> float:
    """
    NVD API 2.0 can return multiple metric blocks; choose the highest baseScore we can find.
    """
    best = 0.0
    if not isinstance(metrics, dict):
        return best

    # Common metric sets:
    # "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if not isinstance(arr, list):
            continue
        for m in arr:
            cvss = (m or {}).get("cvssData") or {}
            base = cvss.get("baseScore")
            if isinstance(base, (int, float)) and float(base) > best:
                best = float(base)
    return best

def iso_utc(dt: datetime) -> str:
    # NVD expects ISO 8601 with timezone offset, e.g. 2025-12-16T00:00:00.000+00:00
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

def fetch_nvd_page(params: dict) -> dict:
    # Basic retry for transient 429/5xx
    for attempt in range(1, 6):
        r = requests.get(NVD_CVES_ENDPOINT, headers=HEADERS, params=params, timeout=90)
        if r.status_code in (429, 500, 502, 503, 504):
            wait = min(2 ** attempt, 30)
            print(f"[!] NVD returned {r.status_code}. Retrying in {wait}s...")
            time.sleep(wait)
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError("NVD API kept failing after retries.")

def update_from_nvd(days_back: int, kev_set: set[str], max_total: int | None = None):
    """
    Pull CVEs changed in the last N days using lastModStartDate/lastModEndDate.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)

    print(f"[*] Querying NVD API 2.0 for last modified window: {start.date()} -> {end.date()}")

    start_index = 0
    results_per_page = 2000  # max allowed by NVD API 2.0
    total_upserted = 0
    rows_buffer = []
    cpe_rows_buffer: list[tuple] = []

    while True:
        params = {
            "lastModStartDate": iso_utc(start),
            "lastModEndDate": iso_utc(end),
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }

        data = fetch_nvd_page(params)
        vulns = data.get("vulnerabilities", []) or []
        if not vulns:
            break

        for entry in vulns:
            cve_obj = (entry or {}).get("cve") or {}
            if not isinstance(cve_obj, dict) or not cve_obj:
                continue

            cve_id = (cve_obj.get("id") or "").strip()
            if not cve_id:
                continue

            # English description
            descriptions = cve_obj.get("descriptions") or []
            desc = ""
            for d in descriptions:
                if (d or {}).get("lang") == "en":
                    desc = (d or {}).get("value") or ""
                    break
            if not desc and descriptions:
                desc = (descriptions[0] or {}).get("value") or ""

            published = (cve_obj.get("published") or "")[:10]

            metrics = cve_obj.get("metrics") or {}
            score = pick_cvss_score(metrics)

            # Port/service-based mapping
            service = guess_service(desc)
            if not service:
                continue

            is_exploited = 1 if cve_id.upper() in kev_set else 0

            # cves table upsert row
            rows_buffer.append((cve_id, service, desc, score, published, is_exploited))

            # CPE capture (for later CPE-based matching)
            cpes = extract_cpes_from_cve(cve_obj) or set()
            for cpe in cpes:
                cpe_rows_buffer.append((cve_id, cpe))

        # Flush periodically
        if len(rows_buffer) >= 5000:
            upsert_rows(rows_buffer)               # writes to cves table
            upsert_cpe_rows(cpe_rows_buffer)       # writes to cve_cpes table (you must implement)
            total_upserted += len(rows_buffer)
            print(f"[*] Upserted {total_upserted} CVE rows so far...")
            rows_buffer.clear()
            cpe_rows_buffer.clear()

        total_results = int(data.get("totalResults", 0) or 0)
        start_index += results_per_page

        if max_total and (total_upserted + len(rows_buffer)) >= max_total:
            print(f"[*] Reached max_total={max_total}, stopping early.")
            break

        if start_index >= total_results:
            break

    # Final flush
    if rows_buffer:
        upsert_rows(rows_buffer)
        upsert_cpe_rows(cpe_rows_buffer)
        total_upserted += len(rows_buffer)

    print(f"[+] NVD API update complete. Rows upserted: {total_upserted}")

def main():
    if not NVD_API_KEY:
        print("[!] ERROR: NVD_API_KEY is not set. Set it and re-run.")
        print("    PowerShell:  setx NVD_API_KEY \"your_key\"")
        return

    create_db()
    kev_set = load_cisa_kev_set()

    # Change this if you want (7 is a good default for “updates”)
    days_back = int(os.getenv("NVD_DAYS_BACK", "7"))

    update_from_nvd(days_back=days_back, kev_set=kev_set)

    print("[+] Done. Database at:", DB_PATH)

if __name__ == "__main__":
    main()
