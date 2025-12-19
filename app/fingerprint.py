
# app/fingerprint.py (enhanced)
# Drop-in replacement adding richer active fingerprints with strict timeouts.
from __future__ import annotations

import socket
import ssl
import subprocess
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Optional deps (present in your project already): requests, zeroconf, pysnmp
import requests
from xml.etree import ElementTree

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    ZEROCONF_AVAILABLE = True
except Exception:
    ZEROCONF_AVAILABLE = False

# Silence urllib3 warnings for self-signed certs (local devices)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Helpers ----------

def _with_timeout(fn, timeout: float, *args, **kwargs):
    """Run a function in a thread with timeout, return None on timeout or exception."""
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _TO
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(fn, *args, **kwargs)
        try:
            return fut.result(timeout=timeout)
        except _TO:
            return None
        except Exception:
            return None

def reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    def _rdns():
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return None
    return _with_timeout(_rdns, timeout)

def grab_ssh_banner(ip: str, timeout: float = 1.0) -> Optional[str]:
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            if data:
                line = data.decode(errors="ignore").strip()
                # Example: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
                return line
    except Exception:
        pass
    return None

def grab_http_banner(ip: str, port: int, tls: bool = False, timeout: float = 1.5) -> Dict[str, Any]:
    url = f"http{'s' if tls else ''}://{ip}:{port}/"
    out: Dict[str, Any] = {}
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        out["status"] = r.status_code
        if "Server" in r.headers:
            out["server"] = r.headers.get("Server")
        m = re.search(r"<title>(.*?)</title>", r.text or "", re.IGNORECASE | re.DOTALL)
        if m:
            out["title"] = m.group(1).strip()
    except Exception:
        pass
    # TLS certificate peek
    if tls and "server" not in out:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=ip) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                cert = s.getpeercert()
                subj = None
                if cert:
                    for tup in cert.get("subject", []):
                        for k, v in tup:
                            if k == "commonName":
                                subj = v
                    out["tls_common_name"] = subj
                    out["tls_issuer"] = dict(cert.get("issuer", [("", "")])) if cert.get("issuer") else None
        except Exception:
            pass
    return out

def ssdp_discover(ip: str, timeout: float = 1.5) -> Dict[str, Any]:
    """
    Send an SSDP M-SEARCH to multicast and collect replies from this IP.
    If LOCATION present, fetch device description for model/manufacturer.
    """
    result: Dict[str, Any] = {}
    msg = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        'MAN: "ssdp:discover"',
        "MX: 1",
        "ST: ssdp:all", "", ""
    ]).encode()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.settimeout(timeout)
        # allow multiple sockets to use the same PORT number
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Send to multicast; devices will unicast back
        s.sendto(msg, ("239.255.255.250", 1900))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, (src, _) = s.recvfrom(8192)
                if src != ip:
                    continue
                text = data.decode(errors="ignore")
                headers: Dict[str, str] = {}
                for line in text.split("\r\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().upper()] = v.strip()
                result["headers"] = headers
                loc = headers.get("LOCATION")
                if loc:
                    try:
                        r = requests.get(loc, timeout=timeout, verify=False)
                        xml = ElementTree.fromstring(r.content)
                        # robust search without strict namespaces
                        model = xml.find(".//{*}modelName")
                        manu = xml.find(".//{*}manufacturer")
                        dtype = xml.find(".//{*}deviceType")
                        fname = xml.find(".//{*}friendlyName")
                        result["device_xml"] = {
                            "friendlyName": fname.text if fname is not None else None,
                            "manufacturer": manu.text if manu is not None else None,
                            "modelName": model.text if model is not None else None,
                            "deviceType": dtype.text if dtype is not None else None,
                            "location": loc,
                        }
                    except Exception:
                        pass
                break  # keep first match from this IP
            except socket.timeout:
                break
    except Exception:
        pass
    return result

def snmp_sysdescr(ip: str, communities: List[str] = ["public", "private"], timeout: float = 1.0) -> Optional[str]:
    try:
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity, getCmd
        )
    except Exception:
        return None

    OID = "1.3.6.1.2.1.1.1.0"  # sysDescr.0
    for comm in communities:
        try:
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(comm, mpModel=1),
                    UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity(OID)),
                )
            )
            if errorIndication or errorStatus:
                continue
            for name, val in varBinds:
                return str(val)
        except Exception:
            continue
    return None

def try_nmap_os(ip: str, timeout: float = 6.0) -> Optional[str]:
    """If nmap is installed, run a quick OS guess (-O --osscan-guess -F -Pn)."""
    import shutil, subprocess
    if not shutil.which("nmap"):
        return None
    try:
        # Keep it fast-ish: fast scan ports, no host discovery, guess OS
        proc = subprocess.run(
            ["nmap", "-O", "--osscan-guess", "-F", "-Pn", ip],
            capture_output=True, text=True, timeout=timeout
        )
        out = proc.stdout
        m = re.search(r"OS details:\s*(.+)", out)
        if m:
            return m.group(1).strip()
        m = re.search(r"Running:\s*(.+)", out)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return None

def mdns_services_for_ip(ip: str, timeout: float = 2.0) -> List[Dict[str, Any]]:
    if not ZEROCONF_AVAILABLE:
        return []
    services = [
        "_workstation._tcp.local.",
        "_ssh._tcp.local.",
        "_smb._tcp.local.",
        "_afpovertcp._tcp.local.",
        "_ipp._tcp.local.",
        "_ipps._tcp.local.",
        "_printer._tcp.local.",
        "_googlecast._tcp.local.",
        "_airplay._tcp.local.",
        "_hap._tcp.local.",  # HomeKit
        "_raop._tcp.local.",
        "_http._tcp.local.",
        "_device-info._tcp.local.",
    ]

    found: List[Dict[str, Any]] = []

    class _Listener(ServiceListener):
        def add_service(self, zc, typ, name):
            try:
                info = zc.get_service_info(typ, name, 500)
                if not info:
                    return
                addrs = []
                for b in info.addresses:
                    try:
                        addrs.append(socket.inet_ntoa(b))
                    except Exception:
                        pass
                if ip in addrs:
                    found.append({
                        "type": typ,
                        "name": name,
                        "properties": {k.decode() if isinstance(k, bytes) else k:
                                       v.decode() if isinstance(v, (bytes, bytearray)) else v
                                       for k, v in (info.properties or {}).items()},
                        "port": info.port,
                    })
            except Exception:
                pass

        def remove_service(self, zc, typ, name):  # not used
            pass

        def update_service(self, zc, typ, name):  # not used
            pass

    zc = Zeroconf()
    listener = _Listener()
    browsers = [ServiceBrowser(zc, s, listener) for s in services]
    try:
        time.sleep(timeout)
    finally:
        for b in browsers:
            try: b.cancel()
            except Exception: pass
        try: zc.close()
        except Exception: pass
    return found

# ---------- Main entry points ----------

def fingerprint_device(ip: str, mac: str | None = None, vendor: str | None = None, total_timeout: float = 5.0) -> Dict[str, Any]:
    """Run a battery of quick probes and return a merged fingerprint dict."""
    started = time.time()
    results: Dict[str, Any] = {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
    }

    probes = {
        "rdns": lambda: reverse_dns(ip),
        "ssh": lambda: grab_ssh_banner(ip),
        "http80": lambda: grab_http_banner(ip, 80, tls=False),
        "https443": lambda: grab_http_banner(ip, 443, tls=True),
        "ssdp": lambda: ssdp_discover(ip),
        "snmp": lambda: snmp_sysdescr(ip),
        "mdns": lambda: mdns_services_for_ip(ip),
        "nmap_os": lambda: try_nmap_os(ip),
    }

    # Run probes concurrently with per-probe timeouts
    per_probe_timeout = 1.8  # each probe tries to keep it snappy
    with ThreadPoolExecutor(max_workers=8) as ex:
        fut_map = {ex.submit(_with_timeout, fn, per_probe_timeout): name for name, fn in probes.items()}
        for fut in as_completed(fut_map):
            name = fut_map[fut]
            try:
                results[name] = fut.result(timeout=per_probe_timeout + 0.2)
            except Exception:
                results[name] = None
            if time.time() - started > total_timeout:
                break

    # Light classification heuristics
    results["guess"] = classify(results)

    return results

def classify(fp: Dict[str, Any]) -> Optional[str]:
    """Derive a best-effort device guess from the evidence gathered."""
    # SNMP vendor hints
    sys = (fp.get("snmp") or "").lower() if isinstance(fp.get("snmp"), str) else ""
    if "printer" in sys or "laserjet" in sys or "officejet" in sys or "ipp" in sys:
        return "Printer"
    if "cisco" in sys or "juniper" in sys or "mikrotik" in sys or "ubiquiti" in sys:
        return "Network device"

    # SSDP / UPnP
    dd = fp.get("ssdp") or {}
    dx = (dd.get("device_xml") or {}) if isinstance(dd, dict) else {}
    dtype = (dx.get("deviceType") or "").lower()
    man = (dx.get("manufacturer") or "").lower()
    model = (dx.get("modelName") or "").lower()
    if "mediarenderer" in dtype or "mediaplayer" in model or "roku" in model or "chromecast" in model:
        return "Streaming device / TV"
    if "ipcamera" in dtype or "camera" in model:
        return "IP camera"

    # mDNS services
    md = fp.get("mdns") or []
    types = {d.get("type") for d in md if isinstance(d, dict)}
    if "_googlecast._tcp.local." in types:
        return "Chromecast / Cast-enabled"
    if "_airplay._tcp.local." in types or "_raop._tcp.local." in types:
        return "Apple device / AirPlay"
    if "_hap._tcp.local." in types:
        return "HomeKit accessory"
    if "_workstation._tcp.local." in types and "_smb._tcp.local." in types:
        return "Desktop/Laptop (likely)"
    if "_printer._tcp.local." in types or "_ipp._tcp.local." in types or "_ipps._tcp.local." in types:
        return "Printer"

    # HTTP(S) banners
    http = fp.get("http80") or {}
    https = fp.get("https443") or {}
    server = ((http.get("server") or "") + " " + (https.get("server") or "")).lower()
    if "synology" in server or "qnap" in server or "asuswrt" in server or "openwrt" in server or "unifi" in server:
        return "NAS / Router UI"
    if "nginx" in server and ("tls_common_name" in https or "title" in https):
        # too generic otherwise
        return "Web service"

    # SSH banner
    ssh = (fp.get("ssh") or "").lower()
    if "openssh" in ssh:
        return "Unix-like host (SSH)"

    return None

# Batch wrapper compatible with your existing code
def fingerprint_all(devices: Dict[str, Dict[str, str]], processes: int = 8) -> Dict[str, Dict[str, Any]]:
    """
    devices: {ip: {"mac": "...", "vendor": "..."}}
    """
    def _one(item):
        ip, meta = item
        return ip, fingerprint_device(ip, meta.get("mac"), meta.get("vendor"))

    out: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=processes) as ex:
        futs = [ex.submit(_one, it) for it in devices.items()]
        for fut in as_completed(futs):
            ip, fp = fut.result()
            out[ip] = fp
    return out
