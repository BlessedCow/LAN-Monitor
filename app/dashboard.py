# app/dashboard.py
from flask import Flask, render_template, request, redirect, send_file, jsonify, Response
from app.scanner import scan_network_with_mac
from app.scanner import scan_tcp_ports, scan_udp_ports
from app.scanner import get_own_ip
from app.utils import load_labels, save_labels
from app.utils import load_open_ports, save_open_ports
from app.utils import save_last_scan, load_last_scan
from app.vuln_lookup import PORT_SERVICE_MAP, query_local_vulns, load_cisa_kev
from app.fingerprint import fingerprint_all
import platform
import subprocess
import re
import json
import os
import io
import csv
from typing import Optional

app = Flask(__name__, template_folder="../templates", static_folder="../static")

def build_device_choices():
    scan = load_last_scan() or {}
    labels = load_labels() or {}
    choices = []
    
    for ip, info in scan.items():
        mac = (info.get("mac") or "").lower()
        vendor = info.get("vendor") or ""
        label = (load_labels() or {}).get(mac, "")
        display = f"{ip} | {label or vendor or mac or 'Unknown'}"
        choices.append((ip, display))
    choices.sort(key=lambda x: x[0])
    return choices

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

            # If not connected to Wi-Fi says "State: "
            state = re.search(r"^\s*State\s*:\s*(.+)$", output, re.MULTILINE)
            if state and state.group(1).strip().lower() != "connected":
                return "Not Wi-Fi"

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

        return "Unknown / Wired"

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
def index():
    own_ip = get_own_ip()

    devices_info = scan_network_with_mac(
        base_ip="192.168.1.",
        start=1,
        end=254,
        ping_timeout=0.3,
        max_workers=100,
        arp_timeout=2.0,
    )

    # sort by latency and rename to the variable your template expects
    sorted_list = sorted(devices_info.items(), key=lambda item: item[1].get("latency", 999999))
    devices = {ip: info for ip, info in sorted_list}
    # persist last scan
    save_last_scan(devices)

    ssid = get_current_ssid()
    labels = load_labels()
    warning = not bool(devices)

    return render_template(
        "index.html",
        devices=devices,
        ssid=ssid,
        labels=labels,
        warning=warning,
        own_ip=own_ip
    )
    
    
    
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

@app.route("/scan_ports", methods=["POST"])
def scan_ports():
    ip = request.form.get("ip")
    port_input = request.form.get("ports", "")

    try:
        ports = [int(p.strip()) for p in port_input.split(",") if p.strip().isdigit()]
    except ValueError:
        ports = []

    if not ports:
        ports = [22, 80, 443, 445, 3389]  # fallback default ports

    # Run the scanners
    open_tcp = scan_tcp_ports(ip, ports)
    open_udp = scan_udp_ports(ip, ports)

    save_open_ports({ip: {"tcp": open_tcp, "udp": open_udp}})

    return render_template("port_results.html", ip=ip, tcp=open_tcp, udp=open_udp, cve_map={})

@app.route("/fingerprints")
def fingerprints():
    devices = scan_network_with_mac()
    raw = fingerprint_all(devices)

    def adapt(fp: dict) -> dict:
        http80 = fp.get("http80") or {}
        https443 = fp.get("https443") or {}

        return {
            "mac": fp.get("mac"),
            "vendor": fp.get("vendor"),
            "hostname": fp.get("rdns") or "",
            "os_guess": fp.get("nmap_os") or fp.get("guess") or "",
            "snmp": fp.get("snmp") or "",
            "ssdp": (fp.get("ssdp") or {}).get("device_xml")
                    or (fp.get("ssdp") or {}).get("headers") or "",
            "netbios": "",  # not collected by the enhanced module
            "service_banners": {
                "ftp": "",
                "smtp": "",
                "pop3": "",
                "imap": "",
                "telnet": "",
                "http": (" ".join(filter(None, [
                    (http80.get("server") or "").strip(),
                    (http80.get("title") or "").strip()
                ]))).strip(),
                "https": (" ".join(filter(None, [
                    (https443.get("server") or "").strip(),
                    (https443.get("title") or https443.get("tls_common_name") or "").strip()
                ]))).strip(),
                "ssh": fp.get("ssh") or "",
            }
        }

    fingerprinted = {ip: adapt(info) for ip, info in raw.items()}
    labels = load_labels()
    return render_template("fingerprints.html", fingerprints=fingerprinted, labels=labels)

@app.route("/vulnerabilities")
def vulnerabilities():
    own_ip = get_own_ip()

    # Build dropdown list once
    device_choices = build_device_choices()

    # Safe min_cvss parsing (handles "" and junk)
    raw_min = (request.args.get("min_cvss") or "").strip()
    try:
        min_cvss = float(raw_min) if raw_min != "" else 0.0
    except ValueError:
        min_cvss = 0.0

    cisa_only = request.args.get("cisa", "false").lower() == "true"
    mode = request.args.get("mode", "severity").lower()  # severity | recent | full
    sort_desc = request.args.get("sort") == "true"
    summary_only = request.args.get("summary") == "true"

    # Pull plenty, then we sort/trim ourselves
    max_results = 200

    # IMPORTANT: no trailing commas here
    port_data = load_open_ports() or {}
    labels = load_labels() or {}
    results = {}

    def safe_float(x):
        try:
            return float(x)
        except Exception:
            return 0.0

    def safe_date_key(s: str):
        # expects "YYYY-MM-DD" or ""
        return (s or "")

    # Build IP -> label (labels are keyed by MAC)
    # This assumes scan_network_with_mac returns {ip: {"mac": "..."}}
    ip_to_label = {}
    try:
        scan = scan_network_with_mac()
        for ip, info in (scan or {}).items():
            mac = (info.get("mac") or "").lower()
            if mac and mac in labels:
                ip_to_label[ip] = labels.get(mac, "")
    except Exception:
        ip_to_label = {}

    for ip, ports in (port_data or {}).items():
        results[ip] = []

        if not isinstance(ports, dict):
            continue

        tcp_ports = ports.get("tcp") or []
        udp_ports = ports.get("udp") or []

        if not isinstance(tcp_ports, list):
            tcp_ports = []
        if not isinstance(udp_ports, list):
            udp_ports = []

        for port in (tcp_ports + udp_ports):
            service = PORT_SERVICE_MAP.get(port)
            if not service:
                continue

            cves = query_local_vulns(
                service,
                min_score=min_cvss,
                cisa_only=cisa_only,
                max_results=max_results
            ) or []

            for cve in cves:
                results[ip].append({
                    "port": port,
                    "service": service,
                    "cve_id": cve.get("id") or cve.get("cve_id") or "",
                    "description": cve.get("desc") or cve.get("description") or "",
                    "cvss": safe_float(cve.get("score") or cve.get("cvss") or 0),
                    "published": cve.get("published") or "",
                    "cisa": bool(cve.get("cisa") or cve.get("is_exploited") or 0),
                })

        # Sort + trim per device based on mode
        if mode == "recent":
            results[ip].sort(key=lambda x: safe_date_key(x.get("published", "")), reverse=True)
            results[ip] = results[ip][:10]
        elif mode == "severity":
            results[ip].sort(key=lambda x: x.get("cvss", 0.0), reverse=True)
            results[ip] = results[ip][:10]
        elif mode == "full":
            if sort_desc:
                results[ip].sort(key=lambda x: x.get("cvss", 0.0), reverse=True)

    return render_template(
        "vulnerabilities.html",
        results=results,
        device_choices=device_choices,
        ip_to_label=ip_to_label,
        mode=mode,
        sort_desc=sort_desc,
        summary_only=summary_only,
        own_ip=own_ip,
        request=request,
    )
@app.route("/scan_all_ports")
def scan_all_ports():
    
    devices = scan_network_with_mac()
    port_data = {}

    common_ports = [22, 80, 443, 445, 3389]

    for ip in devices:
        tcp = scan_tcp_ports(ip, common_ports)
        udp = scan_udp_ports(ip, common_ports)
        port_data[ip] = {"tcp": tcp, "udp": udp}

    save_open_ports(port_data)
    return redirect("/vulnerabilities")

@app.route("/scan_single", methods=["POST"])
def scan_single():
    ip_or_mac = request.form.get("ip_or_mac", "").strip()
    port_data = load_open_ports()

    # Basic validation for IP or MAC format
    is_ip = re.match(r"\d{1,3}(\.\d{1,3}){3}", ip_or_mac)
    is_mac = re.match(r"([0-9a-fA-F]{2}[:\-]){5}([0-9a-fA-F]{2})", ip_or_mac)

    if is_ip:
        ip = ip_or_mac
    elif is_mac:
        # Try to resolve MAC to IP from current scan
        scan = scan_network_with_mac()
        ip = next((k for k, v in scan.items() if v.get("mac", "").lower() == ip_or_mac.lower()), None)
        if not ip:
            return f"MAC {ip_or_mac} not found", 404
    else:
        return "Invalid IP or MAC address format", 400

    # Scan selected ports
    ports = [22, 80, 443, 445, 3389]
    tcp = scan_tcp_ports(ip, ports)
    udp = scan_udp_ports(ip, ports)
    port_data[ip] = {"tcp": tcp, "udp": udp}
    save_open_ports(port_data)

    return redirect("/vulnerabilities")

@app.route("/clear_ports", methods=["POST"])
def clear_ports():
    save_open_ports({})
    return redirect("/vulnerabilities")

@app.route('/export/json')
def export_json():
    port_data = load_open_ports()
    scan_data = scan_network_with_mac()
    labels = load_labels()

    export_data = {}
    for ip, ports in port_data.items():
        mac = scan_data.get(ip, {}).get("mac", "unknown").lower()
        label = labels.get(mac, "")
        export_data[ip] = {
            "mac": mac,
            "label": label,
            "ports": ports,
            "vendor": scan_data.get(ip, {}).get("vendor"),
            "latency": scan_data.get(ip, {}).get("latency"),
        }

        buf = io.BytesIO(json.dumps(export_data, indent=2).encode("utf-8"))
        buf.seek(0)
        return send_file(
            buf,
            mimetype="application/json",
            as_attachment=True,
            download_name="vulnerability_report.json"
    )

@app.route('/export/csv')
def export_csv():
    port_data = load_open_ports()
    scan_data = scan_network_with_mac()
    labels = load_labels()
    cisa_kev = load_cisa_kev()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "MAC", "Label", "Vendor", "Latency_ms", "Protocol", "Port"])

    for ip, ports in port_data.items():
        mac = scan_data.get(ip, {}).get("mac", "unknown").lower()
        label = labels.get(mac, "")
        vendor = scan_data.get(ip, {}).get("vendor") or ""
        latency = scan_data.get(ip, {}).get("latency") or ""
            
        for p in ports.get("tcp", []):
            writer.writerow([ip, mac, label, vendor, latency, "tcp", p])
        for p in ports.get("udp", []):            
            writer.writerow([ip, mac, label, vendor, latency, "udp", p])
    
    data = output.getvalue().encode("utf-8")
    buf = io.BytesIO(data)
    buf.seek(0)
    return send_file(
        buf,
        mimetype="text/csv",
        as_attachment=True,
        download_name="vulnerability_report.csv"
    )
def run():
    app.run(host="0.0.0.0", port=5000)