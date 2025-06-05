# app/scanner.py

from concurrent.futures import ThreadPoolExecutor, as_completed
import ping3
import subprocess
import re
import platform
import time
import requests
from typing import Optional

# Import and load the local OUI‐to‐vendor map (Wireshark “manuf” file fallback)
from app.oui_lookup import load_manuf_file, lookup_vendor_offline
load_manuf_file()

# Attempt to import Scapy for raw ARP; if unavailable, SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, srp, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def select_active_iface() -> Optional[str]:
    """
    Return a non-loopback interface name for Scapy to send ARP on.
    Skip any interface whose name contains “loopback” or “pseudo”.
    """
    if not SCAPY_AVAILABLE:
        return None

    for iface in get_if_list():
        lower = iface.lower()
        if "loopback" in lower or "pseudo" in lower:
            continue
        try:
            conf.iface = iface
            _ = conf.iface.mac  # will error if invalid
            return iface
        except Exception:
            pass
    return None


def ping_host(ip: str, timeout: float = 0.3) -> tuple[str, Optional[float]]:
    """
    Send a single ICMP echo request to `ip`. Return (ip, latency_seconds) if replied,
    otherwise (ip, None).
    """
    try:
        latency = ping3.ping(ip, timeout=timeout, size=32)
        return (ip, latency) if latency else (ip, None)
    except Exception:
        return (ip, None)


def raw_arp_scan(network_cidr: str = "192.168.1.0/24", timeout: float = 2.0) -> dict[str, str]:
    """
    Broadcast one ARP “who-has” over `network_cidr` using Scapy+Npcap.
    Return { ip: mac } for each ARP reply. Must run as Administrator/root.
    """
    iface = select_active_iface()
    if not iface:
        return {}

    conf.iface = iface
    arp_request = ARP(pdst=network_cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    try:
        answered, _ = srp(packet, timeout=timeout, verbose=False, iface=iface)
    except Exception:
        return {}

    ip_to_mac: dict[str, str] = {}
    for sent, recv in answered:
        ip_to_mac[recv.psrc] = recv.hwsrc
    return ip_to_mac


def os_arp_table() -> dict[str, str]:
    """
    Run “arp -a” (Windows) or “arp -n” (Linux/macOS) and parse { ip: mac }.
    """
    system = platform.system().lower()
    cmd = ["arp", "-a"] if system.startswith("win") else ["arp", "-n"]
    try:
        raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return {}

    arp_map: dict[str, str] = {}
    mac_regex = r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
    ip_regex = r"(\d{1,3}(?:\.\d{1,3}){3})"
    pattern = re.compile(rf"{ip_regex}.*?{mac_regex}")

    for line in raw.splitlines():
        match = pattern.search(line)
        if match:
            ip_addr = match.group(1)
            mac_addr = match.group(2).replace("-", ":").lower()
            arp_map[ip_addr] = mac_addr
    return arp_map


def lookup_oui_vendor(mac: str) -> Optional[str]:
    """
    1) Try the online API (mac2vendor.com).  
    2) If that fails or returns no result, fall back to lookup_vendor_offline().
    """
    if not mac:
        return None

    hexonly = mac.replace(":", "").replace("-", "").lower()
    if len(hexonly) < 6:
        return None
    OUI = hexonly[:6]

    # Try online API first
    url = f"https://mac2vendor.com/api/v4/mac/{OUI}"
    try:
        r = requests.get(url, timeout=2.0)
        data = r.json()
        if data.get("success") and data.get("payload"):
            vendor = data["payload"][0].get("vendor")
            if vendor:
                return vendor
    except Exception:
        pass

    # Fallback to the local Wireshark manuf file
    return lookup_vendor_offline(mac)


def scan_network_with_mac(
    base_ip: str = "192.168.1.",
    start: int = 1,
    end: int = 254,
    ping_timeout: float = 0.3,
    max_workers: int = 100,
    arp_timeout: float = 2.0
) -> dict[str, dict[str, Optional[object]]]:
    """
    1) Ping every IP base_ip{start}..base_ip{end} in parallel → latency_map { ip: latency }.
    2) Attempt raw ARP scan → ip_to_mac. If too few MACs, fallback to OS ARP table.
    3) For each ping-responsive IP:
         mac    = ip_to_mac.get(ip) or None
         vendor = lookup_oui_vendor(mac) if mac else None
         latency = round(latency_sec * 1000, 2)
       Return a dict:
       {
         "192.168.1.5":  { "mac": "aa:bb:cc:dd:ee:ff" or None,
                           "vendor": "Vendor Name" or None,
                           "latency": 12.34 },
         ...
       }
    """
    # --- Step 1: Ping sweep ---
    latency_map: dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(ping_host, f"{base_ip}{i}", ping_timeout): f"{base_ip}{i}"
            for i in range(start, end + 1)
        }
        for fut in as_completed(future_to_ip):
            ip_addr = future_to_ip[fut]
            _, latency = fut.result()
            if latency is not None:
                latency_map[ip_addr] = latency

    if not latency_map:
        return {}

    # --- Step 2: Raw ARP via Scapy/Npcap if available ---
    if SCAPY_AVAILABLE:
        cidr = f"{base_ip}0/24"
        ip_to_mac = raw_arp_scan(cidr, timeout=arp_timeout)
        # If ARP returns fewer than 50% of ping-responsive IPs, try OS ARP as fallback
        if len(ip_to_mac) < len(latency_map) * 0.5:
            time.sleep(0.2)
            ip_to_mac = os_arp_table()
    else:
        ip_to_mac = os_arp_table()

    # --- Step 3: Combine and look up vendors ---
    results: dict[str, dict[str, Optional[object]]] = {}
    for ip_addr, latency_sec in latency_map.items():
        mac_addr = ip_to_mac.get(ip_addr)
        vendor = lookup_oui_vendor(mac_addr) if mac_addr else None
        results[ip_addr] = {
            "mac":     mac_addr,
            "vendor":  vendor,
            "latency": round(latency_sec * 1000, 2)
        }

    return results


if __name__ == "__main__":
    # Quick standalone test: run "python app/scanner.py"
    data = scan_network_with_mac(
        base_ip="192.168.1.",
        start=1,
        end=254,
        ping_timeout=0.3,
        max_workers=100,
        arp_timeout=2.0
    )
    for ip, info in sorted(data.items(), key=lambda x: x[1]["latency"]):
        print(f"{ip}    MAC={info['mac']}    Vendor={info['vendor']}    Latency={info['latency']} ms")
