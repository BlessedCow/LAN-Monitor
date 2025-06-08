# app/dashboard.py

from flask import Flask, render_template, request, redirect
from app.scanner import scan_network_with_mac
from app.utils import load_labels, save_labels
import platform
import subprocess
import re
from typing import Optional

app = Flask(__name__, template_folder="../templates", static_folder="../static")

def get_current_ssid() -> str:
    system = platform.system().lower()

    if system == "windows":
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
            )
            match = re.search(r"^\s*SSID\s*:\s*(.+)$", output, re.MULTILINE)
            if match:
                ssid = match.group(1).strip()
                if ssid and "SSID" not in ssid.lower():
                    return ssid
        except Exception:
            pass

        try:
            ipcfg = subprocess.check_output(["ipconfig"], stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
            blocks = re.split(r"Ethernet adapter ", ipcfg)
            for blk in blocks[1:]:
                ip_match = re.search(r"IPv4 Address.*?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", blk)
                if ip_match:
                    ip_addr = ip_match.group(1)
                    if not ip_addr.startswith("127."):
                        return "Ethernet"
        except Exception:
            pass

        return "Unknown"

    elif system == "darwin":
        try:
            output = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                stderr=subprocess.DEVNULL, text=True
            )
            match = re.search(r"^\s*SSID:\s*(.+)$", output, re.MULTILINE)
            if match:
                return match.group(1).strip()
        except Exception:
            pass

        try:
            ipcfg = subprocess.check_output(["ifconfig"], stderr=subprocess.DEVNULL, text=True)
            if re.search(r"^en[0-9]+:.*\n\s*inet\s+((?!127\.)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ipcfg, re.MULTILINE):
                return "Ethernet"
        except Exception:
            pass

        return "Unknown"

    elif system == "linux":
        try:
            ssid = subprocess.check_output(["iwgetid", "-r"], stderr=subprocess.DEVNULL, text=True).strip()
            if ssid:
                return ssid
        except Exception:
            pass

        try:
            ipaddr = subprocess.check_output(["ip", "-4", "addr"], stderr=subprocess.DEVNULL, text=True)
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

    sorted_list = sorted(devices_info.items(), key=lambda item: item[1]["latency"])
    sorted_devices = {ip: info for ip, info in sorted_list}

    ssid = get_current_ssid()
    labels = load_labels()
    return render_template("index.html", devices=sorted_devices, ssid=ssid, labels=labels)


@app.route("/set_label", methods=["POST"])
def set_label():
    mac = request.form.get("mac", "").lower()
    label = request.form.get("label", "")

    if not mac:
        return "Missing MAC address", 400

    labels = load_labels()
    labels[mac] = label
    save_labels(labels)
    return redirect("/")


def run():
    app.run(host="0.0.0.0", port=5000)
