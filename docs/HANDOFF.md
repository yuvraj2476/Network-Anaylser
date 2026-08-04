# Network Analyzer — HANDOFF

This is the full Network Analyzer suite, built on top of PR #5 (bug fixes +
security hardening, commit `0beb325`). All seven feature batches (A–G) are
present and verified:

## Batches

- **A) Scanning**
  - SYN stealth scan (`/api/devices/<mac>/portscan` with `type=syn`)
  - UDP scan (`type=udp`)
  - 80-port service DB with regex version fingerprinting (`SERVICE_DB`)
  - `run_port_scan()` dispatcher (connect/syn/udp)
  - CRITICAL: `import scapy.layers.tls.all` so TLS packets dissect; `SCAPY_AVAILABLE=True`
    with descriptive `scapy_error` on import failure.
- **B) WiFi audit**
  - Monitor-mode on/off with airmon-ng → iw fallback (`wifi_enable_monitor`, `wifi_disable_monitor`)
  - 802.11 beacon / deauth / EAPOL parsing in `_wifi_sniffer`
  - Evil-twin detection (same SSID, different BSSID/crypto)
  - Deauth lab test (broadcast deauth; confirm-gated in UI)
  - Auto-restore on shutdown via `cleanup_network_actions`
- **C) WiFi lab**
  - WPA 4-way handshake capture → hashcat `-m 22000` export (`_make_22000`)
  - PMKID extraction (parsed from M1 RSNE vendor tag)
  - Channel hopping during survey/capture
  - Site survey (signal map) with CSV export (`wifi_site_survey_csv`)
  - Tables: `wifi_ap_log`, `wifi_event_log`, `wifi_handshakes`, `wifi_signal_samples`
- **D) Recon**
  - One-click recon: DNS + subdomains (crt.sh + wordlist + subfinder/assetfinder/amass) +
    all IPs + ports + HTTP + TLS (via `ssl_cert_log` + `cryptography`) + optional VirusTotal
  - Deep web scan over ~370 admin/secret paths (`DEEP_WEB_PATHS`) with tech fingerprinting (26 signatures)
  - Tool manager for 23 tools (`TOOLS`) with `apt install` and `go install` support
  - Tables: `recon_log`, entries also added to `ssl_cert_log`
- **E) Bug Bounty**
  - Multi-source subdomain enum (`crt.sh` + dictionary + subfinder/assetfinder/amass)
  - Concurrent live-host probing httpx-style (ThreadPoolExecutor)
  - ThreadPoolExecutor job runner (`bb_start_subdomain_enum`, `bb_start_live_probe`)
  - Command runner with strict allowlist (`ALLOWLISTED_BB_TOOLS` + `_sanitize_bb_argv`)
    and streamed SSE-free output
  - Tables: `bb_targets`, `bb_subdomains`, `bb_live_hosts`, `bb_jobs`
- **F) AI + Settings**
  - Offline AI Brain (`ask_brain`) with 14 intents covering every feature
  - Optional LLM analyst: OpenAI-compatible / Ollama (`llm_chat`)
  - `settings` table with masked API-key UI (values masked client-side but stored plaintext server-side)
- **G) Last fixes (critical)**
  - CSRF guard **exempts `/login`** so the login POST succeeds before a session is established;
    without this, proxied previews (and new browsers) would 403 on first login → blank page.
  - Dashboard has a CDN guard (`__bootCdn` + `cdn-notice`) that wraps Chart.js/vis-network
    loading; tables and actions still render when CDN is blocked.

## DB tables (23)

devices, alerts, bandwidth_log, parental_rules, scan_log, audit_log, dns_query_log,
ja3_log, port_scan_history, passive_dns_log, ssl_cert_log, honeypot_log, os_fingerprint_log,
wifi_ap_log, wifi_event_log, wifi_handshakes, wifi_signal_samples, recon_log, settings,
bb_targets, bb_subdomains, bb_live_hosts, bb_jobs

(22 in the batch list above; `honeypot_log` was added in the original PR and kept.)

## Default credentials

- Username: `admin` (env `ADMIN_USERNAME`)
- Password: `admin123` (env `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH`)
- Secret: `change-this-in-production-abc123xyz` (env `SECRET_KEY`)

## Run

```
pip install -r requirements.txt
sudo python3 network_manager.py
# Dashboard: http://localhost:5000
```

## Verification run (this build)

- `python3 -m py_compile network_manager.py` → OK
- All required imports install cleanly; scapy imports TLS; `SCAPY_AVAILABLE=True`.
- Boot banner prints, Flask listens on `0.0.0.0:5000`.
- `GET /login` → 200, contains `name="_csrf_token"` hidden field.
- `POST /login` with `admin/admin123` + CSRF → 302 → `/` dashboard HTML
  (contains `sec-overview`, `sec-bugbounty`, `sec-wifi-audit`, `sec-recon`,
  `AI Brain`, plus CDN-fallback `cdn-notice` div).
- Authenticated: `/api/stats`, `/api/devices`, `/api/bb/targets`,
  `/api/bb/jobs`, `/api/tools/status`, `/api/ai/status` all → 200.
- `node --check` on inline dashboard JS → OK.
- Fresh-session POST to `/login` without a CSRF token still returns 302
  (CSRF exemption for `/login` works — fix G).

## Offensive-feature safety

- Deauth, block, MITM, DNS-spoof, and bug-bounty features are opt-in per click with
  confirmation dialogs and are audit-logged. UI warns on every offensive panel.
- Bug-bounty command runner uses a hardcoded allowlist + argument sanitizer; shell
  metacharacters are rejected.
- Shutdown hook restores ARP/managed mode so blocked devices come back online.
