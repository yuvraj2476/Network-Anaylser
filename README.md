# 🔒 Network Analyzer — Security Auditing Suite

A self-hosted Flask dashboard for auditing your own WiFi / LAN: device discovery,
bandwidth, port/vuln scanning, WiFi audit (monitor mode, handshakes, evil-twin,
hashcat 22000 export), one-click recon (subdomains, TLS, deep-web admin-page hunter),
a bug-bounty module with multi-source enumeration + allowlisted command runner, and
an AI Brain with optional LLM integration.

> ⚠️ **Only use on networks you own or have explicit written permission to test.**
> Offensive features (deauth, ARP block, MITM, DNS spoof, recon/bug-bounty) are
> confirm-gated and audit-logged.

## Features

- 🛰 **Device discovery** (ARP + ping fallback), passive OS fingerprinting,
  vendor lookup, custom labels / known-device flag.
- 📶 **Bandwidth monitor** per interface with hog detection (sustained >80% alerting)
  and historical charts.
- 🔌 **Port scanner** – Connect / SYN-stealth / UDP, 80-service DB with regex
  version fingerprinting.
- 🧬 **TLS / JA3** fingerprinting with malware-JA3 blocklist and x509 inspection.
- 🛡️ **Security** – CSRF (session tokens, `/login` exempt for proxied-previews),
  brute-force lockout, security headers, rate limits, audit log, optional Telegram alerts.
- 📡 **WiFi audit** (Linux only) – monitor mode (airmon-ng / iw), site survey,
  channel hopping, evil-twin detection, deauth lab, WPA handshake capture with
  **hashcat `-m 22000`** export, PMKID extraction.
- 🔍 **Recon** – subdomain enumeration (crt.sh + wordlist + subfinder/assetfinder/amass),
  open-port sweep, HTTP/TLS fetch + tech fingerprint, optional VirusTotal,
  deep-web scan over ~370 admin/secret paths.
- 🎯 **Bug Bounty** – target scoping, multi-source enum, httpx-style concurrent probing,
  allowlisted streamed command runner (subfinder/assetfinder/amass/httpx/ffuf/nmap/dig/whois/curl).
- 🧠 **AI Brain** – offline intent engine (no API key) plus optional OpenAI-compatible
  / Ollama LLM analyst.
- ⚙️ **Settings UI** with masked API keys and one-click tool installer (apt / go).

## Quick start

```bash
pip install -r requirements.txt
sudo python3 network_manager.py
# Open http://localhost:5000  (default login: admin / admin123 — CHANGE IT!)
```

### Docker

```bash
docker compose up --build
# Capabilities NET_RAW + NET_ADMIN are needed for ARP/SYN scanning and WiFi.
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_USERNAME` | `admin` | Dashboard username |
| `ADMIN_PASSWORD` | `admin123` | Dashboard password (hashed in memory on boot) |
| `ADMIN_PASSWORD_HASH` | _(optional)_ | Pre-hashed Werkzeug password; overrides `ADMIN_PASSWORD` |
| `SECRET_KEY` | _insecure default_ | Flask session secret — **set this in production** |
| `APP_HOST` | `0.0.0.0` | Bind address |
| `APP_PORT` | `5000` | Bind port |
| `DB_PATH` | `./network_manager.db` | SQLite path |
| `PCAP_DIR` | `./pcaps` | Handshake PCAP output dir |
| `SCAN_INTERVAL` | `30` | Seconds between auto ARP scans |
| `COOKIE_SECURE` | `0` | Set `Secure` flag on session cookie |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | — | Optional alert notifications |
| `VT_API_KEY` | — | VirusTotal key (also editable in Settings) |
| Retention (`RETAIN_ALERTS_DAYS`, `RETAIN_AUDIT_DAYS`, `RETAIN_DNS_DAYS`, `RETAIN_BW_DAYS`, `RETAIN_JA3_DAYS`, `RETAIN_PORT_DAYS`, `RETAIN_WIFI_DAYS`) | defaults 7–90 | Log retention windows |

## Dashboard sections (12)

1. Overview – stats + bandwidth / device-type charts + recent alerts
2. Devices – inventory, labels, block/unblock, port/vuln scan, OS fingerprint
3. Network Map – vis.js graph of gateway and devices
4. Bandwidth – live rates, history, speed test
5. WiFi Audit & Lab – monitor mode, survey, handshakes, event log
6. Recon – one-click recon + deep-web + TLS check
7. Bug Bounty – targets, enum, live-host probe, allowlisted command runner
8. Security – alerts, MITM/rogue-DHCP, JA3, DNS threats, audit log
9. Live Traffic / PCAP – HTTP/DNS/TLS SNI viewer, packet capture
10. AI Brain – offline assistant + optional LLM
11. Settings & Tools – key/value settings, external tool install
12. Reports – security report, passive DNS, port-history

## Default login: `admin` / `admin123`

Set `ADMIN_PASSWORD` (or `ADMIN_PASSWORD_HASH`) and `SECRET_KEY` before
exposing this to anything outside localhost.

## Project layout

```
network_manager.py   # Main Flask app (~4,900 LOC, 233 functions, 75+ routes)
templates/
  login.html         # CSRF-protected login
  dashboard.html     # 12-section SPA-style UI with Chart.js + vis.js + CDN fallback
docs/
  CODE_AUDIT.md      # Security audit notes from PR #5
  HANDOFF.md         # Batch-by-batch handoff spec
Dockerfile, docker-compose.yml, requirements.txt, .gitignore
```

## License

MIT — see `LICENSE`.
