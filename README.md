# LAN Monitor

**LAN Monitor** is a lightweight Python-based web app that scans your local network, identifies connected devices, and checks for common vulnerabilities. It provides a real-time dashboard with latency metrics, MAC vendor lookup, and per-device port/CVE analysis — all accessible via a clean Flask web interface.

## 🔑 Key Features

### 📡 Device Discovery
- **Ping Sweep:** Concurrently pings a specified IP range (e.g. 192.168.1.1–254) to identify responsive hosts.
- **ARP Lookup:** Retrieves MAC addresses using:
  - Raw ARP via Scapy (if Npcap is available)
  - OS ARP cache as fallback (arp -a / arp -n)
- **SSID Detection:** Shows current SSID or Ethernet fallback.
  
### 🏷 Vendor Identification & Labeling
- **Vendor Info:** Matches OUI prefix from MAC to identify vendor.
- **Offline OUI Support:** Includes Wireshark manuf fallback.
- **Custom Labels:** Assign and persist labels per device (by MAC).
  
### 📊 Real-Time Dashboard
- **Built with Flask + Jinja2**
- **Sortable device table with:** IP, MAC, Vendor, Latency, Label
- **Color-coded latency:**
  - 0–50ms → 🟩 Green (#adebb3)
  - 51–100ms → 🟨 Yellow (#e6e8a1)
  - 101–150ms → 🟧 Orange (#d9a65a)
  - 150ms → 🟥 Red (#ce3c3c)
  
### 🔍 Vulnerability Scanning
- Identify open ports and match them against known vulnerabilities from NVD and CISA.
- Scan all devices or target one by IP or MAC.

### 🎯 Open Port Detection
- Scan TCP/UDP ports on any device
- Enter ports manually or use common defaults
  
### 📋 CVE Integration
- **Looks up open ports via:**
  - NVD (National Vulnerability Database)
  - CISA KEV (Known Exploited Vulnerabilities)
- **Flags:**
  - CVE ID, Description, CVSS score, Publish date
  - Highlights CISA-exploited issues
  
### 📌 Filtering & Export
- Filter by CVSS score or CISA flag
- Export all scan results to JSON or CSV
- Option to scan:
  - All devices
  - A single device (by IP or MAC)
- Option to flush scan history via UI

## 🚀 Getting Started

### 1. Clone the Repo:

   git clone https://github.com/BlessedCow/LAN-Monitor.git
   cd LAN-Monitor

### 2. Set Up a Virtual Environment:
  ``` python -m venv .venv ```
   # Windows:
 ``` .venv\Scripts\activate ```
   # macOS/Linux:
 ``` source .venv/bin/activate ```

### 3. Install Dependencies:
 ``` pip install -r requirements.txt ```

### 4. (Windows Only) Install Npcap:
   - Download from https://nmap.org/npcap
   - Enable WinPcap API-compatible mode
   - Run terminal as Administrator

### 5. Launch the App:
   ``` python main.py ```
   Open your browser to: http://localhost:5000
   
---

## 🗂 File Structure

```LAN-Monitor/
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
- **Scan range:** Edit base_ip, start, and end in scanner.py
- **Port lists:** Customize in /scan_ports or /scan_all_ports
- **Latency colors:** Change thresholds in templates/index.html
- **Update OUI file:**
  curl -L https://gitlab.com/wireshark/wireshark/-/raw/master/manuf -o app/oui/manuf
  *or*
  Manually add entries to oui\manuf file
  
📄 License
This project is licensed under the [MIT License](LICENSE).
