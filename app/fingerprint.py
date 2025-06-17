# app/fingerprint.py

import socket
import subprocess
import re
import multiprocessing
import shutil
import socket as sock
import time
from typing import Dict, Any
from pysnmp.hlapi import *

def resolve_hostname(ip: str) -> str:
    try:
        return socket.getfqdn(ip)
    except:
        return "unknown"

def get_os_guess_nmap(ip: str) -> str:
    if not shutil.which("nmap"):
        return "nmap not installed"
    try:
        result = subprocess.run(
            ["nmap", "-O", "-T4", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10
        )
        match = re.search(r"OS details: (.+)", result.stdout)
        if match:
            return match.group(1).strip()
        match = re.search(r"Running: (.+)", result.stdout)
        if match:
            return match.group(1).strip()
    except subprocess.TimeoutExpired:
        return "nmap timeout"
    except Exception:
        return "nmap error"

    return "unknown"

def get_snmp_sysdescr(ip: str, community: str = 'public', port: int = 161, timeout: int = 2) -> str:
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, port), timeout=timeout),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return "SNMP timeout or error"
        for varBind in varBinds:
            return str(varBind[1])
    except Exception:
        return "SNMP unavailable"

def get_ssdp_info(ip: str, timeout: float = 2.0) -> str:
    ssdp_request = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST:239.255.255.250:1900',
        'MAN:"ssdp:discover"',
        'MX:1',
        'ST:ssdp:all', '', ''
    ]).encode()

    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, sock.IPPROTO_UDP)
        s.settimeout(timeout)
        s.sendto(ssdp_request, (ip, 1900))
        data, _ = s.recvfrom(1024)
        return data.decode(errors="ignore").split("\r\n")[0]
    except Exception:
        return "No SSDP response"

def get_netbios_name(ip: str) -> str:
    if not shutil.which("nbtscan"):
        return "nbtscan not installed"
    try:
        result = subprocess.run(
            ["nbtscan", "-v", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=4
        )
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([^\s]+)", result.stdout)
        if match:
            return match.group(2)
    except subprocess.TimeoutExpired:
        return "nbtscan timeout"
    except Exception:
        return "nbtscan error"
    return "unknown"

def fingerprint_device(ip: str, mac: str, vendor: str) -> Dict[str, Any]:
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": resolve_hostname(ip),
        "os_guess": get_os_guess_nmap(ip),
        "snmp": get_snmp_sysdescr(ip),
        "ssdp": get_ssdp_info(ip),
        "netbios": get_netbios_name(ip),
    }

# This must be at the top level (not nested)
def worker(args):
    ip, mac, vendor = args
    return ip, fingerprint_device(ip, mac, vendor)

def fingerprint_all(devices: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
    results = {}
    with multiprocessing.Pool(processes=6) as pool:
        jobs = [(ip, dev.get("mac", ""), dev.get("vendor", "")) for ip, dev in devices.items()]
        for ip, info in pool.map(worker, jobs):
            results[ip] = info
    return results
