import os

# In‐memory map: OUI (6 hex digits) → vendor name
_manuf_map = {}

def load_manuf_file(path=None):
    """
    Parse the local Wireshark 'manuf' file into _manuf_map.
    If 'path' is None, defaults to '../oui/manuf' relative to this module.
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

                raw_oui = parts[0].lower()       # e.g. "00:00:0a"
                vendor  = " ".join(parts[1:]).strip()

                norm = raw_oui.replace(":", "")[:6]  # "00000a"
                _manuf_map[norm] = vendor
    except FileNotFoundError:
        # If the file isn’t found, _manuf_map remains empty
        pass

def lookup_vendor_offline(mac: str):
    """
    Given a full MAC like "aa:bb:cc:dd:ee:ff", return the vendor
    from _manuf_map (e.g. "Cisco") or None if not found.
    """
    if not mac:
        return None

    hexonly = mac.replace(":", "").replace("-", "").lower()
    if len(hexonly) < 6:
        return None

    oui = hexonly[:6]
    return _manuf_map.get(oui)
