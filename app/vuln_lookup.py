import sqlite3
from pathlib import Path

# Define the path to the local database
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "vulns.db"

# Map of common ports to service names
PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 123: "ntp",
    135: "rpc", 139: "smb", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-proxy"
}

def load_cisa_kev():
    """Return a set of CVE IDs that are known to be exploited (from local DB)."""
    kev_set = set()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        for row in c.execute("SELECT cve_id FROM cves WHERE is_exploited = 1"):
            kev_set.add(row[0].upper())
    return kev_set

def query_vulns(service=None, cpes=None, min_score=0, cisa_only=False, limit=100):
    sql = """
        SELECT DISTINCT c.cve_id, c.description, c.score, c.published, c.is_exploited
        FROM cves c
        LEFT JOIN cve_cpes cp ON c.cve_id = cp.cve_id
        WHERE c.score >= ?
    """
    params = [min_score]

    if service:
        sql += " AND c.service = ?"
        params.append(service)

    if cpes:
        sql += " AND cp.cpe IN ({})".format(",".join("?" * len(cpes)))
        params.extend(cpes)

    if cisa_only:
        sql += " AND c.is_exploited = 1"

    sql += " ORDER BY c.score DESC LIMIT ?"
    params.append(limit)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, params)]

def query_local_vulns(service, min_score=0, cisa_only=False, max_results=10):
    """Query CVEs from the local database based on service and filters."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    sql = "SELECT * FROM cves WHERE service = ? AND score >= ?"
    params = [service, min_score]

    if cisa_only:
        sql += " AND is_exploited = 1"

    sql += " ORDER BY score DESC LIMIT ?"
    params.append(max_results)

    rows = cursor.execute(sql, params).fetchall()
    conn.close()

    return [dict(r) for r in rows]
