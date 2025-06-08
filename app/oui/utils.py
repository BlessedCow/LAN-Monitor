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
