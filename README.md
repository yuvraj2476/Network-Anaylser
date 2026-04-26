# Network-Analyzer

A powerful real-time network scanner and management dashboard for your home WiFi. Analyzes the whole network to see which devices are connected and many more features.

![Demo](docs/demo.gif)

## Quick Start

```bash
# Option 1: Run with Docker (recommended)
docker-compose up

# Option 2: Run directly
pip install -r requirements.txt
sudo python3 network_manager.py
```

Open http://localhost:5000 in your browser.

---

# Network Manager Dashboard

A powerful real-time network scanner and management dashboard for your home WiFi.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0+-green)

## Features

- **Device Discovery** — ARP scan to find all devices on your network
- **Real-Time Monitoring** — Auto-refreshing dashboard with live data
- **Device Management** — Name, categorize, and track devices
- **Bandwidth Monitor** — Real-time upload/download speed charts
- **Speed Test** — Built-in internet speed test
- **Network Map** — Interactive topology visualization
- **Device Blocking** — Block devices via ARP spoofing (your network only)
- **Port Scanner** — Scan open ports on any device
- **Network Messaging** — Send messages to Windows devices
- **Alerts** — Get notified when new/unknown devices connect
- **Parental Controls** — Schedule-based device blocking rules
- **WiFi Info** — SSID, signal strength, channel, security
- **Export** — Download device list as CSV or JSON

## Setup

### Option 1: Docker (Recommended)

```bash
docker-compose up
```

### Option 2: Manual Install

### 1. Install Python 3.8+

Download from https://python.org if you don't have it.

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Dashboard

**Linux / macOS** (sudo required for ARP scanning):
```bash
sudo python3 network_manager.py
```

**Windows** (run as Administrator):
```bash
python network_manager.py
```

### 4. Open Dashboard

Open your browser and go to:
```
http://localhost:5000
```

## Requirements

| Package | Purpose |
|---------|---------|
| flask | Web dashboard server |
| scapy | ARP network scanning |
| psutil | System/network stats |
| speedtest-cli | Internet speed test |
| mac-vendor-lookup | Identify device manufacturers |

## How It Works

1. **ARP Scanning** — Sends ARP requests to discover all devices on your local network
2. **Background Scanner** — Automatically scans every 30 seconds
3. **SQLite Database** — Stores device history, alerts, and settings locally
4. **Web Dashboard** — Flask serves a modern dark-themed dashboard

## Controls

| Key | Description |
|-----|-------------|
| Arrow Keys / WASD | Navigate |
| Scan Button | Trigger manual network scan |
| Block/Unblock | Control device network access |
| Edit | Rename and categorize devices |

## Important Notes

- **Run as root/admin** — ARP scanning requires elevated privileges
- **Use on YOUR network only** — Only use on networks you own or have permission to test
- **Device blocking** uses ARP spoofing — this is for educational/home use only
- **Firewall** — You may need to allow Python through your firewall
- If scapy isn't available, it falls back to ping-based scanning (limited)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Permission denied" | Run with `sudo` (Linux/Mac) or as Administrator (Windows) |
| No devices found | Check you're connected to WiFi, try manual scan |
| Scapy import error | `pip install scapy` — on Windows also install Npcap |
| Speed test fails | `pip install speedtest-cli` |
| Port 5000 in use | Edit `APP_PORT` in network_manager.py |

## Tech Stack

- Python 3 + Flask (backend)
- Scapy (network scanning)
- Chart.js (bandwidth charts)
- vis.js (network map)
- SQLite (local database)
- Vanilla JS (frontend)

## License

MIT License — See [LICENSE](LICENSE) for details.

### Disclaimer

**For educational purposes only.** This tool is designed for learning about network security and monitoring your own networks. 

- Only use on networks you own or have explicit permission to test
- Unauthorized network scanning may be illegal in your jurisdiction
- The authors are not responsible for any misuse of this software
