import json
from pathlib import Path
import os

DATA_DIR = Path(__file__).parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
LAST_SCAN_FILE = DATA_DIR / "last_scan.json"
LABELS_FILE = os.path.join(os.path.dirname(__file__), '..', 'labels.json')

def save_last_scan(scan: dict) -> None:
    try:
        LAST_SCAN_FILE.parent.mkdir(parents=True, exist_ok=True)
        LAST_SCAN_FILE.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[!] Failed to save last scan: {e}")

def load_last_scan() -> dict:
    try:
        if not LAST_SCAN_FILE.exists():
            return {}
        return json.loads(LAST_SCAN_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[!] Failed to load last scan: {e}")
        return {}     
            
def load_labels():
    if os.path.exists(LABELS_FILE):
        with open(LABELS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_labels(labels):
    with open(LABELS_FILE, 'w') as f:
        json.dump(labels, f, indent=2)

OPEN_PORTS_FILE = os.path.join(os.path.dirname(__file__), '..', 'open_ports.json')

def load_open_ports():
    if os.path.exists(OPEN_PORTS_FILE):
        with open(OPEN_PORTS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_open_ports(data):
    with open(OPEN_PORTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)
