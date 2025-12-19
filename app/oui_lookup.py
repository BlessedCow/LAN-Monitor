import os
import csv

_manuf_map = {}  # Wireshark manuf
_ieee_map = {}   # IEEE CSV

def load_manuf_file(path=None):
    """
    Load Wireshark manuf into _manuf_map.
    If path is None, defaults to ./oui/manuf
    """
    global _manuf_map
    _manuf_map.clear()

    if path is None:
        base = os.path.dirname(__file__)
        path = os.path.join(base, "oui", "manuf")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                raw_oui = parts[0].lower()
                vendor = " ".join(parts[1:]).strip()
                norm = raw_oui.replace(":", "")[:6]
                _manuf_map[norm] = vendor
    except FileNotFoundError:
        pass

def load_ieee_csv(path=None):
    """
    Load IEEE OUI CSV into _ieee_map.
    If path is None, defaults to ./oui/oui.csv
    """
    global _ieee_map
    _ieee_map.clear()

    if path is None:
        base = os.path.dirname(__file__)
        path = os.path.join(base, "oui", "oui.csv")

    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                mac = row.get("Assignment", "").replace("-", "").upper().strip()
                vendor = row.get("Organization Name", "").strip()
                if len(mac) == 6 and vendor:
                    _ieee_map[mac] = vendor
    except FileNotFoundError:
        pass

def lookup_vendor(mac: str):
    """
    Try to resolve MAC vendor using:
    1. Wireshark manuf
    2. IEEE CSV
    Returns vendor name or 'Unknown'
    """
    if not mac:
        return "Unknown"

    norm = mac.replace(":", "").replace("-", "").lower()
    if len(norm) < 6:
        return "Unknown"

    prefix = norm[:6]
    return (
        _manuf_map.get(prefix)
        or _ieee_map.get(prefix.upper())
        or "Unknown"
    )

# Load both OUI sources at import
load_manuf_file()
load_ieee_csv()
lookup_vendor_offline = lookup_vendor