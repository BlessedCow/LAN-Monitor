# LAN Monitor

**LAN Monitor** is a lightweight Python-based web application that provides a real-time dashboard of devices on your local network. It combines ICMP “ping” sweeps, ARP lookups, and OUI-based vendor identification to show which hosts are online, their MAC addresses, and vendor info—all accessible via a Flask-powered web interface.

---

## 🔑 Key Features

### 📡 Device Discovery
- **Ping Sweep:** Concurrently pings every IP in a specified range (e.g. `192.168.1.1–254`) to find responsive hosts.  
- **ARP Lookup:** Retrieves MAC addresses using:
  - Raw Scapy/Npcap ARP requests (on Windows)
  - OS ARP cache (via `arp -a` on Windows / `arp -n` on Linux/macOS)
- **Offline Fallback:** Uses system ARP table if raw ARP yields few results.

### 🏷 Vendor Identification (OUI Lookup)
- **Online API:** Queries [mac2vendor.com](https://mac2vendor.com) using the OUI prefix of each MAC address.
- **Offline Fallback:** Uses a bundled Wireshark `manuf` file to match OUIs when the API fails or is unavailable.

### 📊 Sortable, Color-Coded Dashboard
- **Tech Stack:** Flask + Jinja2 for real-time rendering.
- **Latency Coloring:**
  - `0–50 ms`: 🟩 Green (`#adebb3`)
  - `51–100 ms`: 🟨 Yellow (`#e6e8a1`)
  - `101–150 ms`: 🟧 Orange (`#d9a65a`)
  - `>150 ms`: 🟥 Red (`#ce3c3c`)
- **Connection Info:** Shows SSID for Wi-Fi or "Ethernet"/"Unknown" for wired connections.

### ⚙️ Easy Deployment
- **Python 3.9+** compatible
- Uses:
  - `Flask`, `ping3`, `scapy`, `requests`, `psutil`
  - Native OS commands for ARP/SSID detection

---

## ⚙️ How It Works

### 1. Ping Sweep
Uses `ping3` and `ThreadPoolExecutor` to send ICMP echo requests to IPs like `192.168.1.1–254`. Hosts that respond are recorded with latency.

### 2. ARP Scan
- **Primary:** Uses Scapy to broadcast ARP who-has requests to the subnet.
- **Fallback:** Parses system ARP cache with `arp -a` or `arp -n` if MACs are missing.

### 3. OUI Vendor Lookup
- Tries [mac2vendor.com](https://mac2vendor.com) first.
- Falls back to Wireshark `manuf` file for offline support.

### 4. Dashboard Rendering
- Route `/` calls `scan_network_with_mac()` and passes host info to a Jinja2 template.
- Columns shown:
  - IP Address
  - MAC Address
  - Vendor
  - Latency (with background color)
- Connection type shown above the table.

---

## 🚀 Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/BlessedCow/LAN-Monitor.git
cd LAN-Monitor
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Npcap (Windows only)
Download and install [Npcap](https://nmap.org/npcap/)  
✅ Enable **WinPcap API-compatible mode**  
⚠️ Run your terminal (CMD or PowerShell) **as Administrator**

### 5. Run the App

```bash
python main.py
```

Open your browser to:  
📍 [http://localhost:5000](http://localhost:5000)

---

## 🗂 File Structure

```
LAN-Monitor/
├── main.py               # Flask entrypoint
├── requirements.txt      # Python dependencies
├── README.md             # Project description
├── .gitignore            # Ignore cache, envs, etc.
│
├── app/
│   ├── __init__.py
│   ├── dashboard.py      # Flask route logic
│   ├── scanner.py        # Ping sweep, ARP, OUI lookup
│   ├── oui_lookup.py     # Offline OUI mapping
│   └── oui/
│       └── manuf         # Wireshark manuf file
│
├── templates/
│   └── index.html        # Jinja2 dashboard template
│
└── static/
    └── style.css         # Dashboard styles
```

---

## 🛠 Customization

- **IP Range:** Adjust `base_ip`, `start`, and `end` in `scan_network_with_mac()`.
- **Threading & Timeouts:** Tune `max_workers`, `ping_timeout`, and `arp_timeout` for performance.
- **Latency Colors:** Modify the thresholds in `templates/index.html`.
- **Update OUI Database:**

```bash
curl -L https://gitlab.com/wireshark/wireshark/-/raw/<commit-hash>/manuf -o app/oui/manuf
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
