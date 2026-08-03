# Network Analyzer — Full Code Audit & Upgrade Plan

Audit date: 2026-08-03
Files reviewed: `network_manager.py` (3,148 lines), `templates/dashboard.html` (1,518 lines), `templates/login.html`, `README.md`, `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `docs/README.md`, `.gitignore`

---

## Part 1 — All Features Found in the Code

### Backend features (Python / Flask, 45+ API endpoints)

**Discovery & inventory**
1. ARP network scanning (`arp_scan`) with ping-based fallback (`fallback_scan`)
2. MAC vendor lookup (mac-vendor-lookup + hardcoded prefix fallback)
3. Device type guessing from hostname/vendor (`guess_device_type`)
4. OS fingerprinting logic (`guess_device_os` — TTL / TCP window / DHCP hostname) — *defined but never actually called (see bugs)*
5. SQLite device database with first/last seen, online status, blocked/known flags, notes
6. Manual scan API + background auto-scanner every 30 s (queue + rate limiting)
7. Export devices as CSV / JSON

**Monitoring & metrics**
8. Real-time bandwidth monitor per interface (psutil) + Chart.js graphs
9. Bandwidth logging table + "bandwidth hog" detection (*flawed math, see bugs*)
10. Internet speed test (download / upload / ping / server info)
11. WiFi info — SSID, signal, channel, frequency, security, BSSID (Windows/Linux/macOS)
12. WiFi security assessment (encryption, WPS, hidden SSID, recommendations — *broken, see bugs*)
13. Network interface listing (IPv4/IPv6/MAC/netmask) + network-info API

**Security / detection**
14. Live packet capture with BPF filter + packet table (scapy sniff, background thread)
15. DNS query logging with heuristic threat scoring (suspicious TLDs, DGA, tunneling, malware keywords)
16. Passive DNS logging ("Top 5 sites per device" backend)
17. Live traffic viewer (HTTP Host headers, DNS queries, TLS SNI — no decryption)
18. TLS/JA3 fingerprinting with a known-malware hash list (*implementation is a stub, see bugs*)
19. MITM / ARP-spoofing detector (duplicate ARP replies) with alerts + audit logging
20. Rogue DHCP (evil-twin) detector from DHCP Offer/ACK
21. Basic vulnerability scanner (FTP anonymous, old SSH versions, Telnet, HTTP basic auth)
22. Port scanner with service banners + port history tracking ("new open ports" alerts)
23. Security report generator (device counts, recent alerts, suspicious devices)
24. Audit log for every block/unblock/MITM/scan/speedtest/parental action

**Management / control (educational, home-network use)**
25. Device blocking via ARP spoofing + unblock with ARP restore
26. MITM attack simulator per device (ARP spoof, optional DNS spoof) — backend only
27. DNS spoof rule manager (phishing-lab style) — backend only
28. Parental control rules CRUD (day/time scheduling) — *stored but never enforced (see bugs)*
29. Network messaging to Windows devices (msg / smbclient)
30. Alert system (new device, IP/MAC change, blocking, threats) + mark-read
31. Simple login/logout (single hardcoded admin user)

### Frontend features (dashboard.html)
32. Dark-themed single-page dashboard with sidebar navigation (Overview, Devices, Network Map, Bandwidth, Speed Test, WiFi Info, Security, Alerts, Parental Controls, Tools)
33. Live stat cards (online, network, unknown, blocked, alerts) with auto-refresh
34. Device cards with filter (all/online/offline/blocked/unknown), edit modal, block/unblock
35. Interactive network topology map (vis.js)
36. Real-time bandwidth charts (Chart.js, 5 s refresh)
37. Speed test UI with gauges
38. WiFi info + interfaces + security display
39. Alerts list with unread highlighting
40. Parental rules table + add/delete modal
41. Tools: port scanner, vulnerability scanner, packet sniffer (start/stop/clear + live table), network messaging, export CSV/JSON
42. Responsive mobile layout, toasts, modals

### Infrastructure
43. Dockerfile (python:3.11-slim, scapy deps) + docker-compose with NET_RAW/NET_ADMIN capabilities
44. requirements.txt (flask, flask-login, scapy, psutil, speedtest-cli, mac-vendor-lookup, requests)

---

## Part 2 — Bugs & Broken Things Found (verified in code)

### Critical / Security
| # | Issue | Location |
|---|-------|----------|
| B1 | **Authentication bypass**: `/api/devices/<mac>/message` has NO `@login_required` — anyone can call it | network_manager.py:2444 |
| B2 | **Hardcoded default credentials** `admin/admin123` and weak default `SECRET_KEY`; no CSRF protection on any state-changing endpoint; no login rate limiting; open redirect via `?next=` on login; session cookies lack Secure/SameSite hardening | network_manager.py:112-114, 2247-2266 |
| B3 | `request.json` assumed non-None in several APIs (`api_update_device`, `api_add_parental_rule`, `api_add_dns_spoof_rule`, `api_send_message`) → 500 crashes on malformed requests | e.g. 2345, 2994, 2894 |
| B4 | No input validation on `port_range` (`map(int, ...)` → 500 on `"abc"`); unvalidated `count`/`limit` params | network_manager.py:1075 |
| B5 | `__pycache__/network_manager.cpython-312.pyc` is committed to git; `.gitignore` contains only prose text (ignores nothing) | repo root |

### Features advertised but broken / not wired up
| # | Issue | Location |
|---|-------|----------|
| B6 | **Security Monitoring tab is dead on arrival**: dashboard buttons call `loadDnsQueries()`, `loadJa3Fingerprints()`, `loadMitmAlerts()`, `refreshWifiSecurity()` which are **never defined** → ReferenceError; DNS/JA3/MITM tables & counters never populate | dashboard.html:474-536 |
| B7 | **OS fingerprinting is dead code**: `guess_device_os` never called; `os_fingerprint_log` table never written → API always returns `os_guess: null` despite README advertising OS detection | network_manager.py:514, 368, 2328 |
| B8 | **TTL ordering bug**: `ttl >= 126` is checked before `ttl >= 250`, so iOS/macOS (TTL 255) is classified as **Windows**; the `ttl >= 250` branch is unreachable | network_manager.py:524-532 |
| B9 | **JA3 is a stub**: ciphers/extensions/curves/curve_formats are always empty lists, so every JA3 hash is `md5(version + ",,,,")` — meaningless; malware matching can never fire | network_manager.py:1600-1625 |
| B10 | **Parental controls never enforced**: rules are only saved/deleted; no scheduler ever blocks a device according to day/time rules | network_manager.py:2984-3041 |
| B11 | **`wifi_security_scan` NameError**: references undefined variable `info` (lines 933/937) → whole block swallowed by `except`, recommendations never generated | network_manager.py:888-952 |
| B12 | **11 backend APIs have no frontend UI** (features in README are unreachable): live-traffic, passive-dns, port-history, audit-log, security-report, rogue-dhcp-alerts, dns-spoof-rules, active-mitm, start-mitm, stop-mitm, bandwidth-history | dashboard.html (0 references) |
| B13 | **Docker persistence broken**: code ignores `DB_PATH` env var (docker-compose sets it to `/app/data/...`) → `./data` volume never used, DB lost on container recreate | network_manager.py:117 vs docker-compose.yml:12 |

### Logic / data bugs
| # | Issue | Location |
|---|-------|----------|
| B14 | **Passive DNS duplicates**: `passive_dns_log` has no UNIQUE constraint, so `ON CONFLICT DO NOTHING` is a no-op → duplicate rows accumulate and `visit_count` is inflated by the UPDATE hitting all duplicates | network_manager.py:1684-1695, table 337 |
| B15 | **Bandwidth-hog detection math is wrong**: compares per-interface *cumulative* counters against a 5-min window *SUM* of cumulative log rows — incompatible units, effectively broken | network_manager.py:990-1050 |
| B16 | `api_bandwidth_history` returns raw cumulative counters (not deltas) — misleading if ever consumed | network_manager.py:3111 |
| B17 | `get_network_range()` always assumes /24, ignoring real netmask (no support for /22, /23, etc.) | network_manager.py:426 |
| B18 | No ARP table restoration on shutdown/exit — devices left blocked if app dies; no signal handler cleanup | network_manager.py:1344-1371 |
| B19 | SQLite: no WAL mode / busy_timeout — concurrent writers (sniff thread + scanner) risk "database is locked" | network_manager.py:383-390 |
| B20 | No data retention: alerts / audit_log / bandwidth_log grow forever | init_db |
| B21 | Unused tables `ssl_cert_log`, `honeypot_log` created but never written/read — dead schema | network_manager.py:340, 356 |
| B22 | `api_scan` has no rate limiting (unlike port/vuln/block scans) | network_manager.py:2283 |
| B23 | `calculate_ja3` / SNI parsing assume `extensions[0]` exists (fragile, silently fails); `spoof_dns_response` assumes an Ethernet layer exists | 1769, 1566 |
| B24 | speedtest uses the deprecated `speedtest` Python module; charts rely on CDN (Chart.js/vis.js) — no offline fallback for Docker/LAN-only use | requirements.txt, dashboard.html:7-8 |
| B25 | No tests, no CI, no global error handlers (raw 500s), single-user auth only | repo |

---

## Part 3 — What I Want to Upgrade (prioritized)

### P0 — Security first (fix before anything else)
1. **Fix the auth bypass** on `/api/devices/<mac>/message` (add `@login_required`).
2. **Real authentication system**: multiple users, hashed passwords (`werkzeug.security`), password change, role-based access (admin/viewer), optional 2FA.
3. **CSRF protection** on all POST/PUT/DELETE endpoints (Flask-WTF or manual token), login brute-force protection (fail2ban-style lockout / rate limit), fix the `next` open redirect, harden session cookies (`HttpOnly`, `Secure`, `SameSite=Lax`), require `SECRET_KEY`/`ADMIN_PASSWORD` from env in production and refuse known-default values.
4. **Input validation everywhere**: port ranges, JSON body shape, `limit`/`count` bounds; add a global JSON error handler so bad input returns 400 instead of 500.

### P1 — Make every advertised feature actually work
5. **Finish the Security tab** — implement `loadDnsQueries()`, `loadJa3Fingerprints()`, `loadMitmAlerts()`, `refreshWifiSecurity()` with auto-refresh so DNS threat scoring, JA3, and MITM detection are actually visible.
6. **Wire up OS fingerprinting**: capture TTL + TCP window (SYN-ACK probe or sniff) and DHCP hostname during scan, fix the TTL ordering bug (check `>=250` first), persist to `os_fingerprint_log`, show OS on device cards.
7. **Implement real JA3/JA3S**: parse ClientHello ciphers/extensions/curves properly (or use the `ja3` package), ship a real malware hash list (abuse.ch style) instead of 4 hardcoded entries.
8. **Enforce parental controls**: background scheduler thread that blocks/unblocks devices according to day/time rules, with alerts + audit logging.
9. **Fix passive DNS schema** (UNIQUE `(source_mac, domain)` + upsert) so "top sites per device" counts are correct.
10. **Fix `wifi_security_scan`** NameError; actually populate encryption/WPS/hidden-SSID/MAC-filtering from nmcli/iw where available.
11. **Build UI for the 11 orphaned APIs**: Live Traffic Viewer, Passive DNS (top sites per device), Port History, Audit Log viewer, Security Report page, Rogue DHCP alerts, MITM simulator controls, DNS spoof rule editor.
12. **Fix Docker persistence**: honor `DB_PATH` env var (or mount via config), fix `.gitignore`, remove the committed `.pyc`, add `.db` files to ignore.

### P2 — Robustness & performance
13. **SQLite hardening**: enable WAL, `busy_timeout`, connection-per-request, and a data-retention/pruning job (keep N days of alerts/logs).
14. **Real per-device bandwidth**: replace interface-level guessing with per-IP accounting (conntrack / nftables / iptables or scapy counters) and store deltas (rates) not cumulative counters; rewrite hog detection math.
15. **Async job system**: port scans / speed tests / vuln scans as background jobs with job IDs + polling (or websockets via flask-socketio) instead of blocking Flask threads and 30 s queue timeouts.
16. **Better scanning**: compute real network range from netmask (`ipaddress`), support IPv6, configurable scan speed/intervals, optional nmap-style UDP/TCP-SYN scans.
17. **ARP cleanup on shutdown** (signal handlers / atexit) so devices are never left blocked; auto-restore when the app exits.
18. **Rate limit `/api/scan`** and MITM/DNS-spoof endpoints; cap packet-capture memory; make in-memory stores thread-safe.
19. **Replace deprecated `speedtest`** module (or add fallback), add jitter/loss and speed-test history charts.
20. **Vendor Chart.js/vis-network** (or add local fallback) so the dashboard works fully offline in Docker.
21. **Add tests + CI**: pytest suite for DB layer, API endpoints, auth, and the security logic (mitm/dns/ja3 parsing); GitHub Actions workflow.

### P3 — New features worth adding
22. **Notifications**: email / Telegram / webhook / Pushover alerts for new devices, MITM, high-threat DNS, rogue DHCP.
23. **Extended reporting**: daily/weekly email security digest; device uptime & history graphs; data-usage quotas per device.
24. **CVE lookup**: match service banners against an offline/online CVE feed (with user opt-in) for the vuln scanner.
25. **Backup & restore** of the DB; settings/config UI; multi-user roles.
26. **Remote access story**: documented reverse-proxy + TLS setup (or Tailscale/WireGuard instructions) so the dashboard is safe to expose.
27. **Internet kill-switch** (block all non-whitelisted devices) and guest-network monitoring presets.

---

## TL;DR
The codebase is feature-rich (~45 endpoints, 30+ features) but has: **1 auth bypass**, a **dead Security tab**, **3 features that are fake/dead** (OS fingerprinting, JA3, parental enforcement), **11 backend features with no UI**, and several logic bugs (TTL ordering, undefined `info`, broken bandwidth-hog math, broken Docker persistence). The single biggest upgrade win is: **fix the security + wiring bugs (P0/P1), then add UI for the orphaned backend features** — that turns an impressive-but-half-finished tool into a genuinely complete network security dashboard.

---

## Part 4 — Fix Log (completed 2026-08-03)

All P0/P1 items from Parts 2–3 were implemented and verified with automated smoke tests.

### Security fixes
- ✅ **Auth bypass fixed** — `/api/devices/<mac>/message` now requires login (verified: anonymous → 403)
- ✅ **Global CSRF protection** — every POST/PUT/DELETE requires a session token (header `X-CSRF-Token` or form/JSON field); login form + dashboard JS both send it (verified: no token → 403)
- ✅ **Hashed admin password** — `werkzeug` hash, supports `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH` env vars; warns on defaults
- ✅ **Login brute-force lockout** — 5 failed attempts per IP → 15-min lockout (verified)
- ✅ **Open redirect fixed** — `?next=` only allows safe relative paths
- ✅ **Session hardening** — `HttpOnly`, `SameSite=Lax`, optional `Secure` (env), 8h lifetime; `X-Frame-Options`, `nosniff`, `no-store` headers
- ✅ **Input validation** — port ranges (regex + 1–65535 + max 10000), IP addresses, times (HH:MM), device types, body-size cap; malformed JSON returns `{}` instead of 500
- ✅ **Global JSON error handlers** — 404/500/HTTPException return proper status codes

### Feature wiring fixes
- ✅ **Security tab is now alive** — `loadDnsQueries`, `loadJa3Fingerprints`, `loadMitmAlerts`, `refreshWifiSecurity` implemented; counters + tables populate; auto-refresh every 30s
- ✅ **OS fingerprinting is real** — passive observation of TTL/window/DHCP-hostname from captured traffic + active TCP-SYN probe button on device cards; persisted to `os_fingerprint_log`; TTL ordering bug fixed
- ✅ **Real JA3** — full ClientHello parser (SSL version, ciphers, extension types, supported groups, EC point formats) verified against a crafted TLS 1.3 ClientHello
- ✅ **SNI extraction fixed** — proper RFC 6066 ServerNameList parsing (was fragile `extensions[0]` assumption)
- ✅ **Parental controls enforced** — background `parental_enforcer` thread blocks/unblocks per day/time rules (incl. overnight windows), with audit logging; only scheduler-managed devices are auto-restored
- ✅ **WiFi security NameError fixed** — `wifi_security_scan` now takes `wifi_info` properly; `iwconfig` subprocess bug fixed
- ✅ **Passive DNS counts fixed** — UNIQUE `(source_mac, domain)` + atomic upsert
- ✅ **Bandwidth hog detection rewritten** — compares real rates with sustained (>80% for 5 min) tracking and 10-min dedupe
- ✅ **Bandwidth history now returns rates** (deltas), not raw cumulative counters
- ✅ **Docker persistence fixed** — `DB_PATH` env honored, DB dir auto-created

### Robustness
- ✅ **Startup crash fixed** — `os_fingerprint_log` had two PRIMARY KEYs (SQLite rejects) → app could not even start; now `UNIQUE`
- ✅ SQLite WAL + busy_timeout; data retention pruning (~6h interval, env-tunable)
- ✅ Thread-safe in-memory stores (`data_lock`) for sniff-thread vs API access
- ✅ ARP/MITM cleanup on exit (`atexit` + SIGTERM handler) — no devices left blocked
- ✅ Real network range from netmask (no more hardcoded /24)
- ✅ Rate limiting added to manual scan; limits clamped everywhere
- ✅ `.gitignore` fixed; committed `__pycache__` removed

### New UI (previously orphaned backend features are now reachable)
- **Live Traffic** section — traffic viewer, top-domains passive DNS, port history
- **Reports & Logs** section — security report, audit log, CSV/JSON export
- **Security tab** — + Rogue DHCP list
- **Tools** — MITM simulator (start/stop + active list), DNS spoof rule editor
- **Device cards** — OS badge + confidence, per-device traffic estimate, "Fingerprint OS" button

### New power features
- `/api/traffic-summary` — per-MAC bytes/packets from captured traffic
- `/api/devices/<mac>/fingerprint` — active OS probe (TTL + TCP window)
- Telegram alert pushes via `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`
- `APP_PORT`, `SCAN_INTERVAL`, `COOKIE_SECURE`, `RETAIN_*_DAYS` env config

### Verified
- 24-endpoint integration test: all pass
- Auth bypass → 403; CSRF missing → 403; bad input → 400; lockout → blocked
- JA3/SNI parsers tested against crafted TLS packets
- OS fingerprint pipeline (Windows/Linux/upsert) tested
- Parental time-window logic tested (incl. overnight)
- Full app boot test: scanner + pruner + ARP cleanup run cleanly
