import json
import os

LABELS_FILE = os.path.join(os.path.dirname(__file__), '..', 'labels.json')

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
