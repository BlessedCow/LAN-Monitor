# app/dashboard.py

from flask import Flask, render_template
from app.scanner import scan_network_with_mac
import platform
import subprocess
import re
from typing import Optional

app = Flask(__name__, template_folder="../templates", static_folder="../static")

def get_current_ssid() -> str:
    """
    1) On Windows: run `netsh wlan show interfaces` to see if Wi-Fi is connected.
       If so, return its SSID.
    2) If no Wi-Fi SSID, run `ipconfig` and check for an “Ethernet adapter” with a valid
       IPv4 Address (not 127.x.x.x). If found, return "Ethernet".
    3) Otherwise return "Unknown".
    """
    system = platform.system().lower()

    if system == "windows":
        # 1) Try Wi-Fi SSID
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
            )
            # Look for a line like "    SSID                   : MyNetworkName"
            match = re.search(r"^\s*SSID\s*:\s*(.+)$", output, re.MULTILINE)
            if match:
                ssid = match.group(1).strip()
                if ssid and "SSID" not in ssid.lower():
                    return ssid
        except Exception:
            pass

        # 2) No Wi-Fi SSID—check ipconfig for Ethernet adapter with an IPv4 address
        try:
            ipcfg = subprocess.check_output(["ipconfig"], stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
            # Split into blocks on “Ethernet adapter” (Windows localization may vary slightly, but usually it’s in English)
            blocks = re.split(r"Ethernet adapter ", ipcfg)
            for blk in blocks[1:]:
                # Look for lines like "   IPv4 Address. . . . . . . . . . . : 192.168.1.100"
                ip_match = re.search(r"IPv4 Address.*?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", blk)
                if ip_match:
                    ip_addr = ip_match.group(1)
                    if not ip_addr.startswith("127."):
                        return "Ethernet"
        except Exception:
            pass

        return "Unknown"

    elif system == "darwin":
        # 1) Try macOS Wi-Fi SSID
        airport_cmd = [
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            "-I",
        ]
        try:
            output = subprocess.check_output(airport_cmd, stderr=subprocess.DEVNULL, text=True)
            match = re.search(r"^\s*SSID:\s*(.+)$", output, re.MULTILINE)
            if match:
                ssid = match.group(1).strip()
                if ssid:
                    return ssid
        except Exception:
            pass

        # 2) Fallback: check for any non-loopback IPv4 on macOS (assume Ethernet)
        try:
            ipcfg = subprocess.check_output(["ifconfig"], stderr=subprocess.DEVNULL, text=True)
            # Find "en0:" or "en1:" etc. with "inet " not "127.0.0.1"
            if re.search(r"^en[0-9]+:.*\n\s*inet\s+((?!127\.)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ipcfg, re.MULTILINE):
                return "Ethernet"
        except Exception:
            pass

        return "Unknown"

    elif system == "linux":
        # 1) Try iwgetid for Wi-Fi SSID
        try:
            ssid = subprocess.check_output(["iwgetid", "-r"], stderr=subprocess.DEVNULL, text=True).strip()
            if ssid:
                return ssid
        except Exception:
            pass

        # 2) Fallback: check `ip addr` for a non-loopback IPv4
        try:
            ipaddr = subprocess.check_output(["ip", "-4", "addr"], stderr=subprocess.DEVNULL, text=True)
            # Look for "inet 192.168.x.x" under an interface not named "lo"
            if re.search(r"inet\s+((?!127\.)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+.*\n\s*link/ether", ipaddr):
                return "Ethernet"
        except Exception:
            pass

        return "Unknown"

    else:
        return "Unknown"


@app.route("/")
def home():
    devices_info = scan_network_with_mac(
        base_ip="192.168.1.",
        start=1,
        end=254,
        ping_timeout=0.3,
        max_workers=100,
        arp_timeout=2.0,
    )

    # Sort by latency (lowest first)
    sorted_list = sorted(devices_info.items(), key=lambda item: item[1]["latency"])
    sorted_devices = {ip: info for ip, info in sorted_list}

    ssid = get_current_ssid()
    return render_template("index.html", devices=sorted_devices, ssid=ssid)


def run():
    app.run(host="0.0.0.0", port=5000)
