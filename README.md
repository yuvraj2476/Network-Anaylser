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

- **Device Discovery** — ARP scan to find all devices on your network (real netmask, not hardcoded /24)
- **Real-Time Monitoring** — Auto-refreshing dashboard with live data
- **Device Management** — Name, categorize, and track devices
- **Bandwidth Monitor** — Real-time upload/download speed charts + history as true rates
- **Speed Test** — Built-in internet speed test
- **Network Map** — Interactive topology visualization
- **Device Blocking** — Block devices via ARP spoofing (your network only) + automatic ARP restore on shutdown
- **Port Scanner** — Scan open ports with service banners, validated ranges, rate limiting
- **Network Messaging** — Send messages to Windows devices (auth required + CSRF protected)
- **Alerts** — New/unknown devices, MITM, rogue DHCP, high-threat DNS, bandwidth hogs
- **Parental Controls** — Schedule-based blocking **actually enforced** by a background scheduler
- **WiFi Info** — SSID, signal strength, channel, security (Windows/Linux/macOS)
- **Export** — Download device list as CSV or JSON
- **OS Fingerprinting** — Passive (from traffic) + active (TCP SYN probe) OS detection with confidence score
- **Live Traffic Viewer** — Real-time HTTP hostnames, DNS queries, TLS SNI (no decryption) with dashboard UI
- **MITM Attack Simulator** — Educational ARP spoofing per-device with optional DNS spoof (phishing lab) — full UI
- **DNS Spoof Simulator** — Redirect domains to fake IPs for phishing awareness training — full UI
- **Rogue DHCP Detector** — Detect evil twin DHCP servers on your network — visible in Security tab
- **Passive DNS Logger** — Track "Top 5 sites" visited per device (accurate visit counts)
- **TLS Fingerprinting (JA3)** — **Real JA3 hash computation** from ClientHello (version, ciphers, extensions, curves, point formats)
- **MITM/ARP Spoof Detector** — Real-time alerts for ARP poisoning attacks
- **Port Scan History** — Track new open ports over time to catch backdoors
- **Bandwidth Hog Alerts** — Alert when an interface sustains >80% bandwidth for 5+ minutes (fixed math)
- **Audit Logging** — Every block/unblock/MITM/parental/scan action logged with timestamp and user — visible in Reports tab
- **Security Report** — One-page summary of device stats, alerts, and suspicious devices
- **Per-Device Traffic Estimates** — Bytes/packets per MAC collected from captured traffic
- **Telegram Alerts** — Optional push notifications for security events
- **Security hardening** — CSRF protection on all mutations, hashed admin password, login brute-force lockout, session cookie hardening, security headers, input validation, rate limits everywhere

## Configuration (Environment Variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECRET_KEY` | dev-only default (warns) | Flask session signing key |
| `ADMIN_USERNAME` | `admin` | Admin login name |
| `ADMIN_PASSWORD` | `admin123` (warns) | Admin password (hashed at startup) |
| `ADMIN_PASSWORD_HASH` | — | Pre-hashed password (e.g. `werkzeug.security.generate_password_hash` output) |
| `DB_PATH` | `./network_manager.db` | SQLite database location (honored by Docker) |
| `APP_PORT` | `5000` | Web port |
| `SCAN_INTERVAL` | `30` | Auto-scan interval (seconds) |
| `COOKIE_SECURE` | `0` | Set `1` to only send cookies over HTTPS |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | — | Enable Telegram alert pushes |
| `RETAIN_*_DAYS` | 7–90 | Data retention windows (alerts, audit, DNS, bandwidth, JA3, ports) |

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
