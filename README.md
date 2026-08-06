# 🔒 Network Analyzer — Security Auditing Suite

A self-hosted Flask dashboard for auditing your own WiFi / LAN: device discovery,
bandwidth, port/vuln scanning, WiFi audit (monitor mode, handshakes, evil-twin,
hashcat 22000 export), one-click recon (subdomains, TLS, deep-web admin-page hunter),
a bug-bounty module with multi-source enumeration + allowlisted command runner, an
AI Brain with optional LLM integration — and **Pro Recon**: a one-click
attack-surface pipeline with risk scoring, snapshot diffing and report export.

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
- 📡 **WiFi pentest wizard** (Linux + root) – adapter/chipset capability scan,
  monitor mode (airmon-ng / iw), site survey, channel hopping, evil-twin
  detection, deauth lab, WPA handshake/PMKID capture exporting **real hashcat
  `-m 22000`** (`WPA*02*`/`WPA*01*`) lines, **one-click full audit job**
  (check → monitor → survey → handshake → report), and a **Crack Lab** that
  runs hashcat / aircrack-ng against your captures with wordlists from
  `wordlists/` (path-traversal-safe picker, live progress, stoppable).
- 🕸 **MITM Lab** – bettercap-style one-click ARP relay wizard: IP-forwarding
  enable/restore, two-way ARP poisoning, auto traffic capture, live
  intercepted HTTP/DNS/TLS-SNI feed, DNS-spoof rule manager, gateway/self
  poisoning guard. TLS contents are **not** decrypted (no sslstrip by design).
- 🔍 **Recon** – subdomain enumeration (crt.sh + wordlist + subfinder/assetfinder/amass),
  open-port sweep, HTTP/TLS fetch + tech fingerprint, optional VirusTotal,
  deep-web scan over ~370 admin/secret paths.
- ⚡ **Pro Recon (one-click)** – one button chains: DNS intelligence
  (A/AAAA/MX/NS/TXT/SOA/CAA + PTR) → subdomain enum → port sweep → HTTP/TLS
  fingerprinting → **security-header grading (A+–F)** → **subdomain-takeover
  detection** (27-service dangling-CNAME fingerprints) → **lookalike-domain radar**
  (typo/homoglyph permutations, resolved + probed) → **keyless RDAP WHOIS + IP intel**
  → **risk-score engine (0–100, prioritized fixes)** → **attack-surface snapshot
  with 12-char DNA fingerprint + diff ("Time Machine")** → **attack-path graph**
  → **HTML report export**. Live phase chips + streaming terminal in the UI.
- 🪤 **Vantage-point canary** – detects transparent proxies/tarpits lying about
  open ports (random closed-canary check) and flags the sweep as unreliable
  instead of reporting 100/100 false positives.
- 🎯 **Bug Bounty** – target scoping, multi-source enum, httpx-style concurrent probing,
  allowlisted streamed command runner (subfinder/assetfinder/amass/httpx/ffuf/nmap/
  nuclei/katana/dig/whois/curl).
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
| `WORDLIST_DIR` | `./wordlists` | Crack-lab wordlist directory |
| `SCAN_INTERVAL` | `30` | Seconds between auto ARP scans |
| `COOKIE_SECURE` | `0` | Set `Secure` flag on session cookie |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | — | Optional alert notifications |
| `VT_API_KEY` | — | VirusTotal key (also editable in Settings) |
| Retention (`RETAIN_ALERTS_DAYS`, `RETAIN_AUDIT_DAYS`, `RETAIN_DNS_DAYS`, `RETAIN_BW_DAYS`, `RETAIN_JA3_DAYS`, `RETAIN_PORT_DAYS`, `RETAIN_WIFI_DAYS`) | defaults 7–90 | Log retention windows |

## Dashboard sections (14)

1. Overview – stats + bandwidth / device-type charts + recent alerts
2. Devices – inventory, labels, block/unblock, port/vuln scan, OS fingerprint
3. Network Map – vis.js graph of gateway and devices
4. Bandwidth – live rates, history, speed test
5. WiFi Audit & Lab – monitor mode, survey, handshakes, pentest wizard, crack lab
6. Recon – classic one-click recon + deep-web + TLS check
7. **Pro Recon** – 🚀 one-click full pipeline, live terminal + phase chips,
   risk score, tabs (subdomains/ports/hosts/DNS/takeover/lookalikes),
   ⏳ Time Machine snapshot diffing, attack graph, HTML report,
   standalone intel tools (DNS dump, header grade, WHOIS, takeover, lookalikes)
8. Bug Bounty – targets, enum, live-host probe, allowlisted command runner
9. Security – alerts, MITM/rogue-DHCP, JA3, DNS threats, audit log
10. Live Traffic / PCAP – HTTP/DNS/TLS SNI viewer, packet capture
11. **MITM Lab** – one-click ARP relay wizard + intercepted traffic feed + DNS spoof rules
12. AI Brain – offline assistant + optional LLM
13. Settings & Tools – key/value settings, external tool install
14. Reports – security report, passive DNS, port-history

## Pro Recon API (Batch H)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/prorecon/start` | POST | Start pipeline `{target, profile: quick\|full}` → `{job_id}` |
| `/api/prorecon/jobs` | GET | Recent jobs |
| `/api/prorecon/jobs/<id>` | GET | Status, phases, live log, full result |
| `/api/recon/dns` | POST | DNS record dump `{target}` |
| `/api/recon/whois` | POST | Keyless RDAP WHOIS `{target}` (domain or IP) |
| `/api/recon/headers` | POST | Security-header grade `{target}` |
| `/api/recon/takeover` | POST | Takeover scan `{target, subdomains[]?}` |
| `/api/recon/lookalikes` | POST | Lookalike radar `{target, probe}` |
| `/api/recon/snapshots` | GET | Attack-surface snapshots (`?target=`) |
| `/api/recon/snapshots/<id>` | GET | One snapshot |
| `/api/recon/snapshots/diff?a=&b=` | GET | Time-Machine diff |
| `/api/recon/graph/<job>` | GET | vis.js attack graph nodes/edges |
| `/api/recon/report/<job>.html` | GET | Downloadable HTML report |

## Testing / CI

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python tests/smoke_test.py      # boots on :5099, logs in, runs 90+ checks
```

The smoke test exercises every API (including a full two-run Pro Recon +
snapshot diff on a live target), the CSRF guard, input validation, and
graceful degradation when root/scapy/WiFi are unavailable. It exits non-zero
on any hard failure.

## Default login: `admin` / `admin123`

Set `ADMIN_PASSWORD` (or `ADMIN_PASSWORD_HASH`) and `SECRET_KEY` before
exposing this to anything outside localhost.

## Project layout

```
network_manager.py   # Main Flask app (~6,100 LOC, 300+ functions, 90+ routes)
templates/
  login.html         # CSRF-protected login
  dashboard.html     # 13-section SPA-style UI with Chart.js + vis.js + CDN fallback
tests/
  smoke_test.py      # End-to-end feature check (90+ assertions, boot-to-API)
docs/
  CODE_AUDIT.md      # Security audit notes from PR #5
  HANDOFF.md         # Batch-by-batch handoff spec
Dockerfile, docker-compose.yml, requirements.txt, .gitignore
```

## License

MIT — see `LICENSE`.
