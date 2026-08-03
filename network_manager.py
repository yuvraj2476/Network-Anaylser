#!/usr/bin/env python3
"""
Network Analyzer — network security auditing suite for your own WiFi.
Run with: sudo python3 network_manager.py
Dashboard: http://localhost:5000

SECURITY FEATURES:
- Authentication required (hashed password, brute-force lockout, CSRF tokens)
- Session hardening + security headers
- Rate limiting on scans/port-scans/vuln-scans/block actions
- Audit logging for all block/unblock/MITM/parental actions
- Parental-control rules actually enforced by a background scheduler
- Real JA3 TLS fingerprinting, OS fingerprinting (passive + active)
- MITM/ARP-spoof detection, rogue DHCP detection, DNS threat scoring

USE ON NETWORKS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST.
"""

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
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from threading import Lock

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
)
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import psutil

# Optional imports for vulnerability scanning — graceful fallback
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

# Optional imports — graceful fallback
try:
    from scapy.all import ARP, Ether, srp, send, conf, sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, TLS, TLSClientHello, DHCP, DNSRR

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Packet capture storage
captured_packets = []
packet_capture_active = False

# Thread-safety lock for all in-memory stores touched by the sniff thread
data_lock = Lock()

# DNS query logging
dns_queries = []
DNS_QUERY_LIMIT = 1000  # Keep last 1000 queries

# ARP table for MITM detection
arp_table = {}  # ip -> set of macs
MITM_ALERTS = []

# Active MITM attacks tracking
active_mitm_attacks = {}  # target_ip -> {thread, active, dns_spoof}

# JA3 fingerprints storage
ja3_fingerprints = []
JA3_LIMIT = 500

# Known malware JA3 hashes (examples - real list would be larger)
KNOWN_MALWARE_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike",
    "51c64c77e60f3980eea918698f018954": "Emotet",
    "73f017cd0d801d6fd1df88b7c9bcff73": "TrickBot",
    "328734b8d9d4e1f8e7d705a3286e19ea": "QakBot",
}

# Traffic viewer storage - live HTTP/DNS queries
live_traffic = []
LIVE_TRAFFIC_LIMIT = 500

# Rogue DHCP detection
ROGUE_DHCP_ALERTS = []

# Per-device traffic estimation (from captured packets)
per_device_traffic = {}  # mac -> {bytes, packets, last_seen}

# Passive OS fingerprint data observed from traffic: ip -> {ttl, window, dhcp_hostname, last_seen}
observed_tcp = {}

# Login brute-force protection
login_attempts = defaultdict(list)
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW = 900  # 15 minutes

# Parental-control scheduler state (only auto-managed devices are auto-restored)
scheduler_blocked = set()

try:
    from mac_vendor_lookup import MacLookup

    mac_lookup = MacLookup()
    try:
        mac_lookup.update_vendors()
    except:
        pass
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    MAC_LOOKUP_AVAILABLE = False

try:
    import speedtest

    SPEEDTEST_AVAILABLE = True
except ImportError:
    SPEEDTEST_AVAILABLE = False

# ============================================================
# CONFIG
# ============================================================
APP_HOST = "0.0.0.0"
APP_PORT = int(os.environ.get("APP_PORT", "5000"))
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_manager.db"),
)
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "30"))  # seconds between auto-scans

# Ensure the database directory exists (important for Docker volumes)
_db_dir = os.path.dirname(DB_PATH)
if _db_dir and not os.path.isdir(_db_dir):
    try:
        os.makedirs(_db_dir, exist_ok=True)
    except OSError as e:
        print(f"[!] Could not create DB directory {_db_dir}: {e}")

# Security config - CHANGE THESE IN PRODUCTION!
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production-abc123xyz")
if SECRET_KEY == "change-this-in-production-abc123xyz":
    print("[!] WARNING: Using default SECRET_KEY. Set SECRET_KEY env var in production!")

DEFAULT_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
# Prefer a hashed password. If only a plaintext ADMIN_PASSWORD is given, hash it.
if os.environ.get("ADMIN_PASSWORD_HASH"):
    ADMIN_PASSWORD_HASH = os.environ["ADMIN_PASSWORD_HASH"]
else:
    ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get("ADMIN_PASSWORD", "admin123"))
if os.environ.get("ADMIN_PASSWORD", "admin123") == "admin123" and not os.environ.get("ADMIN_PASSWORD_HASH"):
    print("[!] WARNING: Using default admin password. Set ADMIN_PASSWORD env var in production!")

# Rate limiting config
MAX_SCAN_QUEUE_SIZE = 10  # Max pending scans
SCAN_RATE_LIMIT = 5  # Max scans per minute per IP

# ============================================================
# FLASK APP
# ============================================================
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Session hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # 2 MB request body cap
)


def generate_csrf_token():
    """Return the CSRF token for the current session, creating it if needed."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


@app.before_request
def csrf_guard():
    """Global CSRF protection for all state-changing requests."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        token = (
            request.headers.get("X-CSRF-Token")
            or request.form.get("_csrf_token")
            or (request.get_json(silent=True) or {}).get("_csrf_token")
        )
        expected = session.get("_csrf_token", "")
        if not expected or not token or not secrets.compare_digest(token, expected):
            return jsonify({"success": False, "error": "CSRF token missing or invalid"}), 403


@app.context_processor
def inject_csrf_token():
    """Make csrf_token() available to all templates."""
    return {"csrf_token": generate_csrf_token}


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "Internal server error"}), 500


@app.errorhandler(Exception)
def unhandled_error(e):
    from werkzeug.exceptions import HTTPException

    if isinstance(e, HTTPException):
        # Keep proper HTTP status codes (405, 413, 429, ...) instead of 500
        return jsonify({"success": False, "error": e.description}), e.code
    print(f"[!] Unhandled error: {e}")
    return jsonify({"success": False, "error": "Internal server error"}), 500


def get_json_body():
    """Safely parse a JSON request body, returning {} when absent/malformed."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}

# ============================================================
# LOGIN MANAGER
# ============================================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access the dashboard."


# ============================================================
# USER CLASS FOR FLASK-LOGIN
# ============================================================
class User(UserMixin):
    """Simple user class for authentication."""
    def __init__(self, username):
        self.id = username
        self.username = username

# Hardcoded admin user - for v1 only!
admin_user = User(DEFAULT_USERNAME)


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    if user_id == DEFAULT_USERNAME:
        return admin_user
    return None


# ============================================================
# RATE LIMITING & SCAN QUEUE
# ============================================================
scan_queue = queue.Queue(maxsize=MAX_SCAN_QUEUE_SIZE)
scan_timestamps = defaultdict(list)  # Track scan times per IP


def check_rate_limit(ip_address):
    """Check if IP is within rate limit for scans."""
    now = time.time()
    # Clean old timestamps (older than 1 minute)
    scan_timestamps[ip_address] = [t for t in scan_timestamps[ip_address] if now - t < 60]
    
    if len(scan_timestamps[ip_address]) >= SCAN_RATE_LIMIT:
        return False
    return True


def record_scan(ip_address):
    """Record a scan timestamp for rate limiting."""
    scan_timestamps[ip_address].append(time.time())


def add_scan_to_queue(scan_func, *args, **kwargs):
    """Add a scan to the queue with rate limiting."""
    if scan_queue.full():
        return False, "Scan queue full. Please wait."
    
    try:
        scan_queue.put((scan_func, args, kwargs), block=False)
        return True, "Scan queued"
    except queue.Full:
        return False, "Scan queue full. Please wait."


def scan_worker():
    """Background worker to process scan queue."""
    while True:
        try:
            scan_func, args, kwargs = scan_queue.get(timeout=1)
            scan_func(*args, **kwargs)
            scan_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[!] Scan error: {e}")


# ============================================================
# DATABASE
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            custom_name TEXT DEFAULT '',
            device_type TEXT DEFAULT 'unknown',
            first_seen TEXT,
            last_seen TEXT,
            is_online INTEGER DEFAULT 0,
            is_blocked INTEGER DEFAULT 0,
            is_known INTEGER DEFAULT 0,
            notes TEXT DEFAULT ''
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            message TEXT,
            device_mac TEXT,
            is_read INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS bandwidth_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            interface TEXT,
            bytes_sent INTEGER,
            bytes_recv INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS parental_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_mac TEXT,
            day_of_week TEXT,
            start_time TEXT,
            end_time TEXT,
            action TEXT DEFAULT 'block'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            devices_found INTEGER,
            new_devices INTEGER,
            scan_duration REAL
        )
    """)
    # AUDIT LOG TABLE - tracks all security actions
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action_type TEXT NOT NULL,
            device_mac TEXT,
            device_ip TEXT,
            user TEXT,
            details TEXT,
            success INTEGER DEFAULT 1
        )
    """)
    # DNS QUERY LOG TABLE - real-time DNS monitoring with threat scoring
    c.execute("""
        CREATE TABLE IF NOT EXISTS dns_query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            source_mac TEXT,
            query_name TEXT,
            query_type TEXT,
            threat_score INTEGER DEFAULT 0,
            threat_category TEXT,
            is_malicious INTEGER DEFAULT 0
        )
    """)
    # JA3 FINGERPRINT TABLE - TLS fingerprinting for malware detection
    c.execute("""
        CREATE TABLE IF NOT EXISTS ja3_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            source_mac TEXT,
            ja3_hash TEXT,
            ja3_raw TEXT,
            matched_malware TEXT,
            is_suspicious INTEGER DEFAULT 0
        )
    """)
    # PORT SCAN HISTORY TABLE - Track open ports over time
    c.execute("""
        CREATE TABLE IF NOT EXISTS port_scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_mac TEXT,
            device_ip TEXT,
            port INTEGER,
            service TEXT,
            first_seen TEXT,
            last_seen TEXT,
            is_new INTEGER DEFAULT 1
        )
    """)
    # PASSIVE DNS TABLE - Log domains visited per device
    c.execute("""
        CREATE TABLE IF NOT EXISTS passive_dns_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_mac TEXT,
            source_ip TEXT,
            domain TEXT,
            visit_count INTEGER DEFAULT 1
        )
    """)
    # Unique per (mac, domain) so visit counts are accurate (fixes inflated counts)
    c.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_passive_dns_mac_domain
        ON passive_dns_log(source_mac, domain)
    """)
    # SSL CERT TABLE - Store SSL certificate info for local servers
    c.execute("""
        CREATE TABLE IF NOT EXISTS ssl_cert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            host TEXT,
            port INTEGER,
            subject TEXT,
            issuer TEXT,
            not_before TEXT,
            not_after TEXT,
            is_self_signed INTEGER DEFAULT 0,
            weak_cipher TEXT,
            days_until_expiry INTEGER
        )
    """)
    # HONEYPOT LOG TABLE - Track connections to fake services
    c.execute("""
        CREATE TABLE IF NOT EXISTS honeypot_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            source_mac TEXT,
            target_port INTEGER,
            protocol TEXT,
            payload TEXT
        )
    """)
    # OS FINGERPRINT TABLE - Store device OS guesses
    c.execute("""
        CREATE TABLE IF NOT EXISTS os_fingerprint_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_mac TEXT UNIQUE,
            os_guess TEXT,
            confidence INTEGER,
            ttl INTEGER,
            tcp_window_size INTEGER,
            dhcp_hostname TEXT
        )
    """)
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


# ============================================================
# NETWORK SCANNING
# ============================================================
def get_default_gateway():
    """Get the default gateway IP."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if gw:
                            return gw
        else:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if line.startswith("default"):
                    return line.split()[2]
    except:
        pass
    return "192.168.1.1"


def get_local_ip():
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def get_network_range():
    """Get the network range for scanning, computed from the real netmask."""
    local_ip = get_local_ip()
    try:
        for _iface, addrs in psutil.net_if_addrs().items():
            if _iface == "lo":
                continue
            for addr in addrs:
                if (
                    addr.family == socket.AF_INET
                    and addr.address == local_ip
                    and addr.netmask
                ):
                    network = ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                    return str(network)
    except Exception as e:
        print(f"[!] Netmask detection failed ({e}), falling back to /24")
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_hostname(ip):
    """Resolve hostname for an IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ""


def get_vendor(mac):
    """Look up vendor from MAC address."""
    if MAC_LOOKUP_AVAILABLE:
        try:
            return mac_lookup.lookup(mac)
        except:
            pass
    # Fallback: common vendor prefixes
    prefix = mac[:8].upper()
    known = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "08:00:27": "VirtualBox",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "AA:BB:CC": "Apple",
    }
    return known.get(prefix, "Unknown")


def guess_device_type(hostname, vendor):
    """Guess device type from hostname and vendor."""
    text = f"{hostname} {vendor}".lower()
    if any(
        k in text
        for k in [
            "iphone",
            "android",
            "galaxy",
            "pixel",
            "huawei",
            "xiaomi",
            "oneplus",
            "oppo",
        ]
    ):
        return "phone"
    if any(k in text for k in ["ipad", "tablet", "fire-hd", "surface"]):
        return "tablet"
    if any(
        k in text for k in ["macbook", "laptop", "thinkpad", "dell", "hp-", "lenovo"]
    ):
        return "laptop"
    if any(k in text for k in ["desktop", "pc", "workstation", "imac"]):
        return "desktop"
    if any(k in text for k in ["printer", "epson", "canon", "brother", "hp-print"]):
        return "printer"
    if any(
        k in text
        for k in [
            "tv",
            "roku",
            "chromecast",
            "fire-tv",
            "appletv",
            "smart-tv",
            "samsung-tv",
            "lg-",
        ]
    ):
        return "tv"
    if any(k in text for k in ["alexa", "echo", "google-home", "homepod", "nest"]):
        return "smart_speaker"
    if any(k in text for k in ["camera", "ring", "arlo", "wyze", "nest-cam"]):
        return "camera"
    if any(k in text for k in ["raspberry", "esp", "arduino"]):
        return "iot"
    if any(k in text for k in ["router", "gateway", "modem"]):
        return "router"
    return "unknown"


def guess_device_os(ttl, tcp_window_size, dhcp_hostname, vendor):
    """
    Guess device OS from TTL, TCP window size, and DHCP hostname.
    Common TTL values: Windows=128, Linux/Android=64, iOS/macOS=255 (initial)
    Common TCP window sizes: Windows=65535/8192, Linux=5792/29200, macOS=65535
    """
    os_guesses = []
    
    # TTL-based OS detection (accounting for hop count, assuming local network = 0-1 hops)
    # NOTE: check highest initial TTLs FIRST so iOS/macOS (255) isn't caught by the >=126 branch
    if ttl >= 250:
        os_guesses.append(("iOS/macOS", 40))  # Initial TTL 255
    elif ttl >= 126:
        os_guesses.append(("Windows", 40))  # Initial TTL 128
    elif ttl >= 120 and ttl < 126:
        os_guesses.append(("Windows (some hops)", 30))
    elif ttl >= 62 and ttl <= 64:
        os_guesses.append(("Linux/Android", 40))  # Initial TTL 64
    elif ttl >= 55 and ttl < 62:
        os_guesses.append(("Linux/Android (some hops)", 30))
    
    # TCP Window size hints
    if tcp_window_size == 65535:
        os_guesses.append(("Windows/macOS", 25))
    elif tcp_window_size == 8192:
        os_guesses.append(("Windows", 30))
    elif tcp_window_size in [5792, 29200, 14480]:
        os_guesses.append(("Linux", 30))
    elif tcp_window_size == 65535 and "Apple" in vendor:
        os_guesses.append(("macOS/iOS", 35))
    
    # DHCP hostname patterns
    if dhcp_hostname:
        hostname_lower = dhcp_hostname.lower()
        if hostname_lower.startswith("android-") or "android" in hostname_lower:
            os_guesses.append(("Android", 45))
        elif hostname_lower.startswith("iphone") or hostname_lower.startswith("ipad"):
            os_guesses.append(("iOS", 45))
        elif hostname_lower.startswith("macbook") or hostname_lower.startswith("imac"):
            os_guesses.append(("macOS", 45))
        elif "win" in hostname_lower or hostname_lower.startswith("desktop"):
            os_guesses.append(("Windows", 35))
        elif "ubuntu" in hostname_lower or "debian" in hostname_lower:
            os_guesses.append(("Linux", 45))
        elif "raspberrypi" in hostname_lower or "pi-" in hostname_lower:
            os_guesses.append(("Raspberry Pi OS", 50))
    
    # Vendor hints
    if "Apple" in vendor:
        os_guesses.append(("iOS/macOS", 30))
    elif "Samsung" in vendor:
        os_guesses.append(("Android", 35))
    elif "Xiaomi" in vendor or "Huawei" in vendor or "OnePlus" in vendor:
        os_guesses.append(("Android", 35))
    elif "Microsoft" in vendor:
        os_guesses.append(("Windows", 40))
    
    # Aggregate scores
    os_scores = {}
    for os_name, score in os_guesses:
        os_scores[os_name] = os_scores.get(os_name, 0) + score
    
    if not os_scores:
        return "Unknown", 0
    
    best_os = max(os_scores, key=os_scores.get)
    confidence = min(os_scores[best_os], 100)
    
    return best_os, confidence


def arp_scan(network_range=None):
    """Perform ARP scan to discover devices."""
    if not SCAPY_AVAILABLE:
        return fallback_scan(network_range)

    if network_range is None:
        network_range = get_network_range()

    try:
        conf.verb = 0
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            mac = received.hwsrc.upper()
            ip = received.psrc
            hostname = get_hostname(ip)
            vendor = get_vendor(mac)
            device_type = guess_device_type(hostname, vendor)
            devices.append(
                {
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "vendor": vendor,
                    "device_type": device_type,
                }
            )
        return devices
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")
        return fallback_scan(network_range)


def fallback_scan(network_range=None):
    """Fallback scan using ping (no root required)."""
    if network_range is None:
        network_range = get_network_range()

    base = network_range.rsplit(".", 1)[0]
    devices = []

    def ping_host(ip):
        try:
            param = "-n" if platform.system() == "Windows" else "-c"
            timeout_param = "-w" if platform.system() == "Windows" else "-W"
            result = subprocess.run(
                ["ping", param, "1", timeout_param, "1", ip],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode == 0:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""
                # Try to get MAC from ARP table
                mac = get_mac_from_arp(ip)
                vendor = get_vendor(mac) if mac else "Unknown"
                device_type = guess_device_type(hostname, vendor)
                devices.append(
                    {
                        "mac": mac or f"UNKNOWN-{ip}",
                        "ip": ip,
                        "hostname": hostname,
                        "vendor": vendor,
                        "device_type": device_type,
                    }
                )
        except:
            pass

    threads = []
    for i in range(1, 255):
        ip = f"{base}.{i}"
        t = threading.Thread(target=ping_host, args=(ip,))
        t.start()
        threads.append(t)
        if len(threads) >= 50:
            for t in threads:
                t.join(timeout=5)
            threads = []

    for t in threads:
        t.join(timeout=5)

    return devices


def get_mac_from_arp(ip):
    """Get MAC address from ARP table."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
        else:
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)

        for line in result.stdout.split("\n"):
            if ip in line:
                parts = line.split()
                for part in parts:
                    if len(part) == 17 and (
                        part.count(":") == 5 or part.count("-") == 5
                    ):
                        return part.upper().replace("-", ":")
    except:
        pass
    return None


def update_devices_db(devices):
    """Update database with scan results."""
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    new_count = 0

    # Mark all devices offline first
    c.execute("UPDATE devices SET is_online = 0")

    for dev in devices:
        existing = c.execute(
            "SELECT * FROM devices WHERE mac = ?", (dev["mac"],)
        ).fetchone()

        if existing:
            c.execute(
                """
                UPDATE devices SET ip = ?, hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
                vendor = CASE WHEN ? != 'Unknown' THEN ? ELSE vendor END,
                device_type = CASE WHEN ? != 'unknown' THEN ? ELSE device_type END,
                last_seen = ?, is_online = 1
                WHERE mac = ?
            """,
                (
                    dev["ip"],
                    dev["hostname"],
                    dev["hostname"],
                    dev["vendor"],
                    dev["vendor"],
                    dev["device_type"],
                    dev["device_type"],
                    now,
                    dev["mac"],
                ),
            )
        else:
            c.execute(
                """
                INSERT INTO devices (mac, ip, hostname, vendor, device_type, first_seen, last_seen, is_online)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """,
                (
                    dev["mac"],
                    dev["ip"],
                    dev["hostname"],
                    dev["vendor"],
                    dev["device_type"],
                    now,
                    now,
                ),
            )
            new_count += 1
            # Alert for new device
            c.execute(
                """
                INSERT INTO alerts (timestamp, alert_type, message, device_mac)
                VALUES (?, 'new_device', ?, ?)
            """,
                (
                    now,
                    f"New device detected: {dev['ip']} ({dev['vendor']})",
                    dev["mac"],
                ),
            )

        # Persist passive OS fingerprint for this device (from observed traffic)
        save_os_fingerprint(c, dev["mac"], dev["ip"], dev["vendor"])

    conn.commit()
    conn.close()
    return new_count


def save_os_fingerprint(conn, mac, ip, vendor):
    """Persist a passive OS fingerprint guess from observed TCP/DHCP data."""
    try:
        with data_lock:
            obs = observed_tcp.get(ip)
            if not obs or not obs.get("ttl"):
                return
            ttl = obs["ttl"]
            window = obs.get("window") or 0
            dhcp_hostname = obs.get("dhcp_hostname") or ""
        os_guess, confidence = guess_device_os(ttl, window, dhcp_hostname, vendor)
        if not os_guess or os_guess == "Unknown":
            return
        conn.execute(
            """
            INSERT INTO os_fingerprint_log (timestamp, device_mac, os_guess, confidence, ttl, tcp_window_size, dhcp_hostname)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_mac) DO UPDATE SET
                timestamp = excluded.timestamp,
                os_guess = excluded.os_guess,
                confidence = excluded.confidence,
                ttl = excluded.ttl,
                tcp_window_size = excluded.tcp_window_size,
                dhcp_hostname = excluded.dhcp_hostname
            """,
            (
                datetime.now().isoformat(),
                mac,
                os_guess,
                confidence,
                ttl,
                window,
                dhcp_hostname,
            ),
        )
    except Exception as e:
        print(f"[!] OS fingerprint save error: {e}")


def active_os_fingerprint(ip):
    """Actively probe a device with a TCP SYN to measure its TTL + window size."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        from scapy.all import sr1

        conf.verb = 0
        result = None
        for port in (80, 443, 22, 8080):
            try:
                resp = sr1(
                    IP(dst=ip) / TCP(dport=port, flags="S"),
                    timeout=2,
                    verbose=0,
                )
                if resp and TCP in resp and resp[TCP].flags & 0x12:  # SYN-ACK
                    result = resp
                    break
            except Exception:
                continue
        if result is None:
            return None
        ttl = result[IP].ttl
        window = result[TCP].window
        with data_lock:
            entry = observed_tcp.setdefault(ip, {})
            entry["ttl"] = ttl
            entry["window"] = window
            entry["last_seen"] = time.time()
            observed_tcp[ip] = entry
        return {"ttl": ttl, "tcp_window_size": window}
    except Exception as e:
        print(f"[!] Active fingerprint error: {e}")
        return None


def notify_alert(message):
    """Push an alert to configured notification channels (Telegram)."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
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


def generate_alert(alert_type, message, device_mac=None):
    """Generate an alert and save to database (+ push notifications)."""
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO alerts (timestamp, alert_type, message, device_mac)
            VALUES (?, ?, ?, ?)
        """, (datetime.now().isoformat(), alert_type, message, device_mac))
        conn.commit()
        conn.close()
        print(f"[!] ALERT [{alert_type}]: {message}")
        notify_alert(f"[{alert_type}] {message}")
    except Exception as e:
        print(f"[!] Error generating alert: {e}")


# ============================================================
# WIFI INFO
# ============================================================
def get_wifi_info():
    """Get WiFi interface information."""
    info = {
        "ssid": "N/A",
        "signal": "N/A",
        "channel": "N/A",
        "frequency": "N/A",
        "security": "N/A",
        "bssid": "N/A",
    }
    try:
        system = platform.system()
        if system == "Windows":
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "SSID" in line and "BSSID" not in line:
                    info["ssid"] = line.split(":", 1)[1].strip()
                elif "Signal" in line:
                    info["signal"] = line.split(":", 1)[1].strip()
                elif "Channel" in line:
                    info["channel"] = line.split(":", 1)[1].strip()
                elif "Radio type" in line:
                    info["frequency"] = line.split(":", 1)[1].strip()
                elif "Authentication" in line:
                    info["security"] = line.split(":", 1)[1].strip()
                elif "BSSID" in line:
                    info["bssid"] = line.split(":", 1)[1].strip()
        elif system == "Linux":
            result = subprocess.run(
                ["iwconfig"], capture_output=True, text=True
            )
            output = result.stdout
            for line in output.split("\n"):
                if "ESSID:" in line:
                    info["ssid"] = (
                        line.split('ESSID:"')[1].split('"')[0]
                        if 'ESSID:"' in line
                        else "N/A"
                    )
                elif "Signal level" in line:
                    if "Signal level=" in line:
                        info["signal"] = line.split("Signal level=")[1].split(" ")[0]
                elif "Frequency:" in line:
                    info["frequency"] = line.split("Frequency:")[1].split(" ")[0]
                elif "Access Point:" in line:
                    info["bssid"] = line.split("Access Point:")[1].strip()

            # Try nmcli for more info
            try:
                result = subprocess.run(
                    [
                        "nmcli",
                        "-t",
                        "-f",
                        "ACTIVE,SSID,SIGNAL,CHAN,SECURITY",
                        "dev",
                        "wifi",
                    ],
                    capture_output=True,
                    text=True,
                )
                for line in result.stdout.split("\n"):
                    if line.startswith("yes:"):
                        parts = line.split(":")
                        if len(parts) >= 5:
                            info["ssid"] = parts[1]
                            info["signal"] = f"{parts[2]}%"
                            info["channel"] = parts[3]
                            info["security"] = parts[4]
            except:
                pass
        elif system == "Darwin":  # macOS
            result = subprocess.run(
                [
                    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
                    "-I",
                ],
                capture_output=True,
                text=True,
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("SSID:"):
                    info["ssid"] = line.split(":", 1)[1].strip()
                elif "agrCtlRSSI:" in line:
                    rssi = int(line.split(":")[1].strip())
                    quality = min(100, max(0, 2 * (rssi + 100)))
                    info["signal"] = f"{quality}% ({rssi} dBm)"
                elif "channel:" in line:
                    info["channel"] = line.split(":", 1)[1].strip()
                elif "BSSID:" in line:
                    info["bssid"] = line.split(":", 1)[1].strip()
    except Exception as e:
        print(f"[!] WiFi info error: {e}")

    return info


def wifi_security_scan(wifi_info=None):
    """Perform basic WiFi security assessment."""
    security_info = {
        "encryption": "Unknown",
        "wps": "Unknown",
        "hidden_ssid": False,
        "mac_filtering": "Unknown",
        "recommendations": [],
    }

    if wifi_info is None:
        wifi_info = get_wifi_info()

    try:
        system = platform.system()
        if system == "Linux" or system == "Darwin":
            # Try to get more detailed WiFi security info
            try:
                # Check if we can get encryption info
                result = subprocess.run(
                    ["iwlist", "auth"], capture_output=True, text=True, timeout=5
                )
                if "WPA3" in result.stdout:
                    security_info["encryption"] = "WPA3 Detected"
                elif "WPA2" in result.stdout or "WPA" in result.stdout:
                    security_info["encryption"] = "WPA/WPA2 Detected"
                elif "WEP" in result.stdout:
                    security_info["encryption"] = "WEP (WEAK)"
                    security_info["recommendations"].append(
                        "Upgrade from WEP to WPA2/WPA3"
                    )
                else:
                    security_info["encryption"] = "Open/Unknown"
            except:
                pass

        # Recommendations based on the WiFi info we already collected
        security_value = wifi_info.get("security", "") or ""
        security_lower = str(security_value).lower()
        if "open" in security_lower:
            security_info["recommendations"].append(
                "Network is open - anyone can connect. Enable WPA2/WPA3 encryption."
            )
        elif "wep" in security_lower:
            security_info["recommendations"].append(
                "WEP encryption is weak - upgrade to WPA2/WPA3"
            )
        elif security_value and "N/A" not in str(security_value):
            security_info["encryption"] = str(security_value)

        if "wpa3" in security_lower:
            security_info["recommendations"].append(
                "WPA3 detected - ensure PMF (Protected Management Frames) is required."
            )

    except Exception as e:
        print(f"[!] WiFi security scan error: {e}")

    return security_info


# ============================================================
# BANDWIDTH MONITORING WITH HOG DETECTION
# ============================================================
prev_counters = {}
bandwidth_hog_alerts = []  # Track bandwidth hog alerts


def get_bandwidth():
    """Get current bandwidth usage for all interfaces."""
    global prev_counters
    counters = psutil.net_io_counters(pernic=True)
    result = {}
    now = time.time()

    for iface, stats in counters.items():
        if iface == "lo" or iface.startswith("veth") or iface.startswith("docker"):
            continue
        if iface in prev_counters:
            prev = prev_counters[iface]
            dt = now - prev["time"]
            if dt > 0:
                dl_speed = (stats.bytes_recv - prev["recv"]) / dt
                ul_speed = (stats.bytes_sent - prev["sent"]) / dt
                result[iface] = {
                    "download_speed": dl_speed,
                    "upload_speed": ul_speed,
                    "total_recv": stats.bytes_recv,
                    "total_sent": stats.bytes_sent,
                    "packets_recv": stats.packets_recv,
                    "packets_sent": stats.packets_sent,
                    "errors_in": stats.errin,
                    "errors_out": stats.errout,
                }
        prev_counters[iface] = {
            "recv": stats.bytes_recv,
            "sent": stats.bytes_sent,
            "time": now,
        }

    return result


hog_tracking = {}  # interface -> {"since": datetime, "pct": float}


def check_bandwidth_hogs():
    """Detect interfaces sustaining >80% of total bandwidth for 5+ minutes.

    Uses the *rate* (bytes/sec) from get_bandwidth() so the comparison is
    apples-to-apples (the old code compared cumulative counters against a
    5-minute sum, which could never work).
    """
    global bandwidth_hog_alerts, hog_tracking

    try:
        now = datetime.now()
        speeds = get_bandwidth()
        total = sum(i["download_speed"] + i["upload_speed"] for i in speeds.values())
        if total <= 0:
            return

        for iface, info in speeds.items():
            iface_rate = info["download_speed"] + info["upload_speed"]
            percentage = (iface_rate / total) * 100

            if percentage > 80:
                if iface not in hog_tracking:
                    hog_tracking[iface] = {"since": now, "pct": percentage}
                    continue
                sustained = (now - hog_tracking[iface]["since"]) >= timedelta(minutes=5)
                if sustained:
                    # Avoid duplicate alerts within 10 minutes per interface
                    recently_alerted = any(
                        a["interface"] == iface
                        and (now - datetime.fromisoformat(a["timestamp"]))
                        < timedelta(minutes=10)
                        for a in bandwidth_hog_alerts
                    )
                    if not recently_alerted:
                        alert_msg = (
                            f"Bandwidth hog detected! Interface {iface} has been "
                            f"using {percentage:.1f}% of total traffic for 5+ minutes"
                        )
                        bandwidth_hog_alerts.append(
                            {
                                "timestamp": now.isoformat(),
                                "interface": iface,
                                "percentage": percentage,
                            }
                        )
                        if len(bandwidth_hog_alerts) > 50:
                            bandwidth_hog_alerts = bandwidth_hog_alerts[-50:]
                        generate_alert("bandwidth_hog", alert_msg)
                        print(f"[!] BANDWIDTH HOG: {alert_msg}")
            else:
                hog_tracking.pop(iface, None)
    except Exception as e:
        print(f"[!] Bandwidth hog check error: {e}")


def log_bandwidth():
    """Log bandwidth to database."""
    counters = psutil.net_io_counters(pernic=True)
    conn = get_db()
    now = datetime.now().isoformat()
    for iface, stats in counters.items():
        if iface == "lo" or iface.startswith("veth") or iface.startswith("docker"):
            continue
        conn.execute(
            """
            INSERT INTO bandwidth_log (timestamp, interface, bytes_sent, bytes_recv)
            VALUES (?, ?, ?, ?)
        """,
            (now, iface, stats.bytes_sent, stats.bytes_recv),
        )
    conn.commit()
    conn.close()
    
    # Check for bandwidth hogs after logging
    check_bandwidth_hogs()


# ============================================================
# PORT SCANNER
# ============================================================
def scan_ports(ip, port_range="1-1024", device_mac=None):
    """Enhanced port scanner with service/version detection and history tracking."""
    start, end = map(int, port_range.split("-"))
    open_ports = []
    common_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                # Try to get service banner for version detection
                banner = grab_service_banner(ip, port)
                service = common_services.get(port, "Unknown")
                version_info = ""
                if banner:
                    version_info = f" - {banner[:100]}"  # Limit banner length

                open_ports.append(
                    {
                        "port": port,
                        "service": service,
                        "state": "open",
                        "banner": banner,
                        "version": version_info.strip(),
                    }
                )
                
                # Log to port_scan_history for tracking new ports over time
                if device_mac:
                    log_port_to_history(device_mac, ip, port, service)
        except:
            pass

    def grab_service_banner(ip, port):
        """Attempt to grab service banner for version detection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))

            # Send appropriate probe based on port
            if port == 21:  # FTP
                sock.send(b"HELP\r\n")
            elif port == 22:  # SSH
                pass  # SSH usually sends banner immediately
            elif port == 25 or port == 587:  # SMTP
                sock.send(b"EHLO test\r\n")
            elif port == 80 or port == 8080 or port == 8000 or port == 8081:  # HTTP
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 443 or port == 8443:  # HTTPS
                pass  # Would need SSL wrapping
            elif port == 110:  # POP3
                pass  # Usually sends banner
            elif port == 143:  # IMAP
                pass  # Usually sends banner
            elif port == 3306:  # MySQL
                pass  # Usually sends banner
            elif port == 3389:  # RDP
                pass  # Would need special handling

            banner = sock.recv(1024)
            sock.close()
            return banner.decode("utf-8", errors="ignore").strip()
        except:
            return None

    threads = []
    for port in range(start, min(end + 1, 65536)):
        t = threading.Thread(target=check_port, args=(port,))
        t.start()
        threads.append(t)
        if len(threads) >= 100:
            for t in threads:
                t.join(timeout=3)
            threads = []

    for t in threads:
        t.join(timeout=3)

    return sorted(open_ports, key=lambda x: x["port"])


def log_port_to_history(device_mac, device_ip, port, service):
    """Log port scan result to history table for tracking changes over time."""
    try:
        conn = get_db()
        now = datetime.now().isoformat()
        
        # Check if this port was already seen for this device
        existing = conn.execute("""
            SELECT * FROM port_scan_history 
            WHERE device_mac = ? AND port = ?
        """, (device_mac, port)).fetchone()
        
        if existing:
            # Update last_seen
            conn.execute("""
                UPDATE port_scan_history SET last_seen = ?, is_new = 0
                WHERE device_mac = ? AND port = ?
            """, (now, device_mac, port))
        else:
            # New port discovered!
            conn.execute("""
                INSERT INTO port_scan_history 
                (timestamp, device_mac, device_ip, port, service, first_seen, last_seen, is_new)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (now, device_mac, device_ip, port, service, now, now))
            
            # Generate alert for new open port
            generate_alert(
                "new_open_port",
                f"New open port detected on {device_ip}: {port} ({service})",
                device_mac
            )
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Error logging port to history: {e}")


def vulnerability_scan(ip):
    """Basic vulnerability scanner for common issues."""
    vulnerabilities = []

    # Check for common vulnerable services
    ports_to_check = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900]

    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                # Check for specific vulnerabilities based on service
                if port == 21:  # FTP - check for anonymous login
                    vuln = check_ftp_anonymous(ip)
                    if vuln:
                        vulnerabilities.append(vuln)
                elif port == 22:  # SSH - check for weak configurations
                    vuln = check_ssh_weak_config(ip)
                    if vuln:
                        vulnerabilities.append(vuln)
                elif port == 23:  # Telnet - inherently insecure
                    vulnerabilities.append(
                        {
                            "port": port,
                            "service": "Telnet",
                            "vulnerability": "Telnet service detected (inherently insecure)",
                            "severity": "high",
                            "description": "Telnet transmits data in plaintext including credentials",
                        }
                    )
                elif port == 80:  # HTTP - check for obvious issues
                    vuln = check_http_basic_auth(ip)
                    if vuln:
                        vulnerabilities.append(vuln)
        except:
            continue

    return vulnerabilities


def check_ftp_anonymous(ip):
    """Check if FTP allows anonymous login."""
    try:
        import ftplib

        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=5)
        ftp.login("anonymous", "anonymous@")
        ftp.quit()
        return {
            "port": 21,
            "service": "FTP",
            "vulnerability": "Anonymous FTP login allowed",
            "severity": "medium",
            "description": "FTP server allows anonymous authentication",
        }
    except:
        return None


def check_ssh_weak_config(ip):
    """Check for weak SSH configurations."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, 22))
        banner = sock.recv(1024)
        sock.close()

        banner_str = banner.decode("utf-8", errors="ignore").lower()
        if "openssh" in banner_str:
            # Extract version if possible
            import re

            version_match = re.search(r"openssh[_\s]+([0-9]+\.[0-9]+)", banner_str)
            if version_match:
                version = version_match.group(1)
                # Check for old, potentially vulnerable versions
                try:
                    major, minor = map(int, version.split("."))
                    if major < 7 or (major == 7 and minor < 4):
                        return {
                            "port": 22,
                            "service": "SSH",
                            "vulnerability": f"Old SSH version detected: {version}",
                            "severity": "medium",
                            "description": f"SSH version {version} may have known vulnerabilities",
                        }
                except:
                    pass
    except:
        pass
    return None


def check_http_basic_auth(ip):
    """Check if HTTP server uses basic auth (transmits credentials in base64)."""
    try:
        import requests

        response = requests.get(f"http://{ip}", timeout=5, verify=False)
        if response.status_code == 401:
            www_auth = response.headers.get("www-authenticate", "")
            if "basic" in www_auth.lower():
                return {
                    "port": 80,
                    "service": "HTTP",
                    "vulnerability": "HTTP Basic Authentication detected",
                    "severity": "medium",
                    "description": "HTTP Basic Authentication transmits credentials in base64 encoding",
                }
    except:
        pass
    return None


# ============================================================
# DEVICE BLOCKING (ARP Spoofing — own network only)
# ============================================================
blocking_threads = {}


def block_device(target_ip, gateway_ip):
    """Block a device by ARP spoofing (requires root + scapy)."""
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed"

    def spoof_loop(target_ip, gateway_ip):
        try:
            target_mac = get_mac_from_arp(target_ip)
            if not target_mac:
                return
            while blocking_threads.get(target_ip, {}).get("active", False):
                # Tell target that we are the gateway
                send(
                    ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip),
                    verbose=0,
                )
                # Tell gateway that we are the target
                send(ARP(op=2, pdst=gateway_ip, psrc=target_ip), verbose=0)
                time.sleep(1)
        except:
            pass

    blocking_threads[target_ip] = {"active": True}
    t = threading.Thread(target=spoof_loop, args=(target_ip, gateway_ip), daemon=True)
    t.start()
    blocking_threads[target_ip]["thread"] = t
    return True, "Device blocked"


def unblock_device(target_ip, gateway_ip):
    """Restore ARP tables to unblock device."""
    if target_ip in blocking_threads:
        blocking_threads[target_ip]["active"] = False
        time.sleep(2)
        # Restore correct ARP
        if SCAPY_AVAILABLE:
            try:
                target_mac = get_mac_from_arp(target_ip)
                gateway_mac = get_mac_from_arp(gateway_ip)
                if target_mac and gateway_mac:
                    send(
                        ARP(
                            op=2,
                            pdst=target_ip,
                            hwdst=target_mac,
                            psrc=gateway_ip,
                            hwsrc=gateway_mac,
                        ),
                        count=5,
                        verbose=0,
                    )
                    send(
                        ARP(
                            op=2,
                            pdst=gateway_ip,
                            hwdst=gateway_mac,
                            psrc=target_ip,
                            hwsrc=target_mac,
                        ),
                        count=5,
                        verbose=0,
                    )
            except:
                pass
        del blocking_threads[target_ip]
    return True, "Device unblocked"


# ============================================================
# MITM ATTACK SIMULATOR (Educational - Start/Stop per device)
# ============================================================
def start_mitm_attack(target_ip, enable_dns_spoof=False, fake_ip=None):
    """
    Start MITM attack simulation on a single target device.
    For educational purposes only - demonstrates ARP spoofing vulnerability.
    """
    global active_mitm_attacks
    
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed"
    
    if target_ip in active_mitm_attacks and active_mitm_attacks[target_ip].get("active", False):
        return False, "MITM attack already running on this target"
    
    target_mac = get_mac_from_arp(target_ip)
    if not target_mac:
        return False, "Could not resolve target MAC address"
    
    gateway_ip = get_default_gateway()
    gateway_mac = get_mac_from_arp(gateway_ip)
    if not gateway_mac:
        return False, "Could not resolve gateway MAC address"
    
    # Use provided fake IP or default to local server for DNS spoof
    if fake_ip is None:
        fake_ip = get_local_ip()
    
    def mitm_loop(target_ip, gateway_ip, target_mac, gateway_mac, dns_spoof_enabled, fake_dns_ip):
        try:
            while active_mitm_attacks.get(target_ip, {}).get("active", False):
                # ARP spoof target: tell target we are gateway
                send(
                    ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip),
                    verbose=0,
                )
                # ARP spoof gateway: tell gateway we are target
                send(
                    ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip),
                    verbose=0,
                )
                
                # If DNS spoofing enabled, also intercept DNS queries
                if dns_spoof_enabled:
                    # This is handled in packet_handler via DNS response spoofing
                    pass
                
                time.sleep(1)
        except Exception as e:
            print(f"[!] MITM loop error: {e}")
        finally:
            # Cleanup: restore ARP tables
            try:
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=3, verbose=0)
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=3, verbose=0)
            except:
                pass
    
    active_mitm_attacks[target_ip] = {"active": True, "dns_spoof": enable_dns_spoof, "fake_ip": fake_ip}
    t = threading.Thread(
        target=mitm_loop, 
        args=(target_ip, gateway_ip, target_mac, gateway_mac, enable_dns_spoof, fake_ip), 
        daemon=True
    )
    t.start()
    active_mitm_attacks[target_ip]["thread"] = t
    
    # Log to audit
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, device_ip, user, details, success)
        VALUES (?, 'start_mitm', ?, ?, ?, ?)
    """,
        (datetime.now().isoformat(), target_ip, current_user.username if current_user.is_authenticated else "system", 
         f"MITM started with DNS spoof={enable_dns_spoof}", 1),
    )
    conn.commit()
    conn.close()
    
    return True, f"MITM attack simulation started on {target_ip}"


def stop_mitm_attack(target_ip):
    """Stop MITM attack simulation on a target device."""
    global active_mitm_attacks
    
    if target_ip not in active_mitm_attacks:
        return False, "No MITM attack running on this target"
    
    active_mitm_attacks[target_ip]["active"] = False
    time.sleep(2)  # Wait for loop to stop and ARP restoration
    
    if target_ip in active_mitm_attacks:
        del active_mitm_attacks[target_ip]
    
    # Log to audit
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, device_ip, user, details, success)
        VALUES (?, 'stop_mitm', ?, ?, ?, ?)
    """,
        (datetime.now().isoformat(), target_ip, current_user.username if current_user.is_authenticated else "system",
         "MITM stopped", 1),
    )
    conn.commit()
    conn.close()
    
    return True, f"MITM attack simulation stopped on {target_ip}"


def get_active_mitm_attacks():
    """Get list of currently active MITM attacks."""
    global active_mitm_attacks
    result = []
    for ip, info in active_mitm_attacks.items():
        result.append({
            "target_ip": ip,
            "active": info.get("active", False),
            "dns_spoof_enabled": info.get("dns_spoof", False),
            "fake_ip": info.get("fake_ip", "")
        })
    return result


# ============================================================
# DNS SPOOF SIMULATOR (Educational - Phishing Lab)
# ============================================================
DNS_SPOOF_RULES = {}  # domain -> fake_ip

def add_dns_spoof_rule(domain, fake_ip):
    """Add a DNS spoof rule - when target queries domain, return fake_ip."""
    global DNS_SPOOF_RULES
    with data_lock:
        DNS_SPOOF_RULES[domain.lower()] = fake_ip
    return True, f"DNS spoof rule added: {domain} -> {fake_ip}"


def remove_dns_spoof_rule(domain):
    """Remove a DNS spoof rule."""
    global DNS_SPOOF_RULES
    with data_lock:
        if domain.lower() in DNS_SPOOF_RULES:
            del DNS_SPOOF_RULES[domain.lower()]
            return True, f"DNS spoof rule removed: {domain}"
    return False, "Rule not found"


def get_dns_spoof_rules():
    """Get all active DNS spoof rules."""
    global DNS_SPOOF_RULES
    with data_lock:
        return [{"domain": d, "fake_ip": ip} for d, ip in DNS_SPOOF_RULES.items()]


def spoof_dns_response(packet, domain, original_dns_server):
    """Craft a fake DNS response returning our fake IP."""
    fake_ip = DNS_SPOOF_RULES.get(domain.lower(), get_local_ip())
    
    # Craft DNS response packet
    dns_response = Ether(
        src=packet[Ether].dst,  # Our MAC
        dst=packet[Ether].src   # Target MAC
    ) / IP(
        src=original_dns_server,  # Pretend to be DNS server
        dst=packet[IP].src
    ) / UDP(
        sport=53,
        dport=packet[UDP].dport
    ) / DNS(
        id=packet[DNS].id,
        qr=1,      # Response
        aa=1,      # Authoritative
        qd=packet[DNS].qd,
        an=DNSRR(
            rrname=domain,
            rdata=fake_ip,
            type="A",
            ttl=60
        )
    )
    
    send(dns_response, verbose=0)
    return fake_ip


# ============================================================
# PACKET SNIFFING WITH DNS, MITM, AND JA3 DETECTION
# ============================================================
def _parse_client_hello(body):
    """Parse a TLS ClientHello body into JA3 components.

    Returns (tls_version, ciphers, extension_types, supported_groups, ec_point_formats)
    per the standard JA3 definition.
    """
    try:
        if len(body) < 4:
            return None
        # handshake header: type(1) + length(3)
        body = body[4:]
        if len(body) < 2:
            return None
        tls_version = struct.unpack(">H", body[0:2])[0]
        p = 2 + 32  # skip version + random
        if p + 1 > len(body):
            return None
        session_id_len = body[p]
        p += 1 + session_id_len
        if p + 2 > len(body):
            return None
        cipher_len = struct.unpack(">H", body[p : p + 2])[0]
        p += 2
        if p + cipher_len > len(body):
            return None
        ciphers = list(struct.unpack(f">{cipher_len // 2}H", body[p : p + cipher_len]))
        p += cipher_len
        if p + 1 > len(body):
            return None
        comp_len = body[p]
        p += 1 + comp_len
        extensions = []
        groups = []
        ec_formats = []
        if p + 2 <= len(body):
            ext_total = struct.unpack(">H", body[p : p + 2])[0]
            p += 2
            ext_end = min(p + ext_total, len(body))
            while p + 4 <= ext_end:
                etype, elen = struct.unpack(">HH", body[p : p + 4])
                p += 4
                edata = body[p : p + elen]
                p += elen
                extensions.append(etype)
                if etype == 10 and len(edata) >= 2:  # supported_groups
                    glen = struct.unpack(">H", edata[0:2])[0]
                    gdata = edata[2 : 2 + glen]
                    for i in range(0, len(gdata) - 1, 2):
                        groups.append(struct.unpack(">H", gdata[i : i + 2])[0])
                elif etype == 11 and len(edata) >= 1:  # ec_point_formats
                    flen = edata[0]
                    ec_formats = list(edata[1 : 1 + flen])
        return tls_version, ciphers, extensions, groups, ec_formats
    except Exception:
        return None


def extract_sni(packet):
    """Extract the SNI hostname from a TLS ClientHello (no decryption)."""
    try:
        if TCP not in packet or Raw not in packet:
            return None
        data = bytes(packet[Raw].load)
        off = 0
        while off + 5 <= len(data):
            rtype, _ver, rlen = (
                data[off],
                struct.unpack(">H", data[off + 1 : off + 3])[0],
                struct.unpack(">H", data[off + 3 : off + 5])[0],
            )
            if rtype == 22 and rlen > 4 and off + 5 + rlen <= len(data):
                hs = data[off + 5 : off + 5 + rlen]
                if hs[0] == 1:  # ClientHello
                    body = hs[4:]
                    p = 2 + 32
                    if p + 1 > len(body):
                        return None
                    p += 1 + body[p]
                    if p + 2 > len(body):
                        return None
                    cipher_len = struct.unpack(">H", body[p : p + 2])[0]
                    p += 2 + cipher_len
                    if p + 1 > len(body):
                        return None
                    p += 1 + body[p]
                    if p + 2 > len(body):
                        return None
                    ext_total = struct.unpack(">H", body[p : p + 2])[0]
                    p += 2
                    ext_end = min(p + ext_total, len(body))
                    while p + 4 <= ext_end:
                        etype, elen = struct.unpack(">HH", body[p : p + 4])
                        p += 4
                        edata = body[p : p + elen]
                        p += elen
                        if etype == 0 and len(edata) >= 5:  # server_name
                            # list_len(2) + name_type(1) + name_len(2) + name
                            nl = struct.unpack(">H", edata[3:5])[0]
                            name = edata[5 : 5 + nl]
                            return name.decode("utf-8", errors="ignore")
                off += 5 + rlen
            else:
                off += 1
        return None
    except Exception:
        return None


def calculate_ja3(packet):
    """Calculate a real JA3 hash from a TLS ClientHello packet.

    Parses the raw TLS record bytes: SSL version, cipher suites, extension
    types, supported groups (curves) and EC point formats, then MD5-hashes the
    canonical JA3 string.
    """
    try:
        if TCP not in packet or Raw not in packet:
            return None, None

        data = bytes(packet[Raw].load)
        off = 0
        while off + 5 <= len(data):
            rtype, _ver, rlen = (
                data[off],
                struct.unpack(">H", data[off + 1 : off + 3])[0],
                struct.unpack(">H", data[off + 3 : off + 5])[0],
            )
            if rtype == 22 and rlen > 4 and off + 5 + rlen <= len(data):
                hs = data[off + 5 : off + 5 + rlen]
                if hs[0] == 1:  # handshake type ClientHello
                    parsed = _parse_client_hello(hs)
                    if not parsed:
                        return None, None
                    tls_version, ciphers, extensions, groups, ec_formats = parsed
                    ja3_raw = (
                        f"{tls_version},"
                        f"{','.join(map(str, ciphers))},"
                        f"{','.join(map(str, extensions))},"
                        f"{','.join(map(str, groups))},"
                        f"{','.join(map(str, ec_formats))}"
                    )
                    return hashlib.md5(ja3_raw.encode()).hexdigest(), ja3_raw
                off += 5 + rlen
            else:
                off += 1
        return None, None
    except Exception as e:
        print(f"[!] JA3 calculation error: {e}")
        return None, None


def process_dns_query(packet, source_ip, source_mac):
    """Process DNS query and calculate threat score. Also logs to passive DNS."""
    global dns_queries
    
    try:
        if not DNS in packet or not DNSQR in packet:
            return
        
        query_name = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
        query_type = packet[DNSQR].type
        
        # Calculate threat score
        threat_score = 0
        threat_category = "benign"
        is_malicious = 0
        
        # Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.link', '.gq', '.ml', '.cf', '.tk', '.ga']
        if any(query_name.lower().endswith(tld) for tld in suspicious_tlds):
            threat_score += 20
            threat_category = "suspicious_tld"
        
        # DGA detection (high entropy, random-looking domains)
        domain_parts = query_name.split('.')
        if len(domain_parts) > 1:
            main_domain = domain_parts[0]
            if len(main_domain) > 15 and sum(c.isdigit() for c in main_domain) > 5:
                threat_score += 30
                threat_category = "possible_dga"
        
        # Known malware domains (simplified list)
        malware_keywords = ['malware', 'virus', 'trojan', 'c2', 'botnet', 'evil']
        if any(kw in query_name.lower() for kw in malware_keywords):
            threat_score += 50
            threat_category = "known_malware"
            is_malicious = 1
        
        # DNS tunneling detection (unusually long subdomains)
        if len(query_name) > 50:
            threat_score += 25
            threat_category = "possible_tunneling"
        
        # Log to memory and database
        dns_entry = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "source_mac": source_mac,
            "query_name": query_name,
            "query_type": str(query_type),
            "threat_score": threat_score,
            "threat_category": threat_category,
            "is_malicious": is_malicious
        }
        
        with data_lock:
            dns_queries.append(dns_entry)
            if len(dns_queries) > DNS_QUERY_LIMIT:
                dns_queries = dns_queries[-DNS_QUERY_LIMIT:]
        
        # Save to dns_query_log (real-time with threat scoring)
        conn = get_db()
        conn.execute("""
            INSERT INTO dns_query_log (timestamp, source_ip, source_mac, query_name, query_type, threat_score, threat_category, is_malicious)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (dns_entry["timestamp"], source_ip, source_mac, query_name, str(query_type), threat_score, threat_category, is_malicious))
        
        # ALSO save to passive_dns_log (for "Top 5 sites per device" feature)
        # Extract base domain (e.g., www.google.com -> google.com)
        base_domain = '.'.join(query_name.split('.')[-2:]) if len(query_name.split('.')) > 1 else query_name
        # Atomic upsert keyed on (source_mac, domain) via the UNIQUE index
        conn.execute("""
            INSERT INTO passive_dns_log (timestamp, source_mac, source_ip, domain, visit_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(source_mac, domain)
            DO UPDATE SET visit_count = visit_count + 1,
                          timestamp = excluded.timestamp,
                          source_ip = excluded.source_ip
        """, (dns_entry["timestamp"], source_mac, source_ip, base_domain))

        conn.commit()
        conn.close()
        
        # Generate alert for high-threat queries
        if threat_score >= 50:
            generate_alert("dns_threat", f"High-threat DNS query: {query_name} (score: {threat_score})", source_mac)
            
    except Exception as e:
        print(f"[!] DNS processing error: {e}")


def detect_mitm(packet):
    """Detect ARP spoofing/MITM attacks by watching for duplicate ARP replies."""
    global arp_table, MITM_ALERTS
    
    try:
        if ARP in packet and packet[ARP].op == 2:  # ARP reply
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc.upper()

            with data_lock:
                if ip not in arp_table:
                    arp_table[ip] = set()
                known_macs = set(arp_table[ip])

            # If we see a different MAC for the same IP, it's likely ARP spoofing
            if mac not in known_macs and len(known_macs) > 0:
                # MITM detected!
                existing_macs = ', '.join(sorted(known_macs))
                alert_msg = f"ARP Spoofing detected! IP {ip} has multiple MACs: {existing_macs}, {mac}"
                
                # Log to MITM alerts
                mitm_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "ip": ip,
                    "new_mac": mac,
                    "existing_macs": existing_macs,
                    "alert": alert_msg
                }
                with data_lock:
                    MITM_ALERTS.append(mitm_entry)
                    if len(MITM_ALERTS) > 100:
                        MITM_ALERTS = MITM_ALERTS[-100:]
                
                # Generate alert
                generate_alert("mitm_attack", alert_msg, mac)
                
                # Log to audit
                conn = get_db()
                conn.execute("""
                    INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, details, success)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (datetime.now().isoformat(), "MITM_DETECTED", mac, ip, alert_msg, 1))
                conn.commit()
                conn.close()
                
                print(f"[!] MITM ATTACK DETECTED: {alert_msg}")
            
            with data_lock:
                arp_table[ip].add(mac)
            
    except Exception as e:
        print(f"[!] MITM detection error: {e}")


def process_tls_fingerprint(packet, source_ip, source_mac):
    """Extract JA3 fingerprint from TLS ClientHello and check against malware database."""
    global ja3_fingerprints
    
    try:
        if TCP in packet and packet[TCP].dport == 443:  # HTTPS
            ja3_hash, ja3_raw = calculate_ja3(packet)
            
            if ja3_hash:
                # Check against known malware
                matched_malware = KNOWN_MALWARE_JA3.get(ja3_hash, "")
                is_suspicious = 1 if matched_malware else 0
                
                ja3_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": source_ip,
                    "source_mac": source_mac,
                    "ja3_hash": ja3_hash,
                    "ja3_raw": ja3_raw[:500] if ja3_raw else "",  # Truncate for storage
                    "matched_malware": matched_malware,
                    "is_suspicious": is_suspicious
                }
                
                with data_lock:
                    ja3_fingerprints.append(ja3_entry)
                    if len(ja3_fingerprints) > JA3_LIMIT:
                        ja3_fingerprints = ja3_fingerprints[-JA3_LIMIT:]
                conn = get_db()
                conn.execute("""
                    INSERT INTO ja3_log (timestamp, source_ip, source_mac, ja3_hash, ja3_raw, matched_malware, is_suspicious)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (ja3_entry["timestamp"], source_ip, source_mac, ja3_hash, ja3_entry["ja3_raw"], matched_malware, is_suspicious))
                conn.commit()
                conn.close()
                
                # Generate alert for malware match
                if matched_malware:
                    alert_msg = f"Malware TLS fingerprint detected! JA3: {ja3_hash} matches {matched_malware}"
                    generate_alert("malware_ja3", alert_msg, source_mac)
                    print(f"[!] MALWARE JA3 DETECTED: {alert_msg}")
                    
    except Exception as e:
        print(f"[!] JA3 processing error: {e}")


def packet_handler(packet):
    """Handle captured packets: DNS, MITM, JA3 detection, live traffic,
    per-device traffic estimation, and passive OS observation."""
    global captured_packets, live_traffic, per_device_traffic, observed_tcp

    # Rogue DHCP detection
    if DHCP in packet and packet.haslayer(DHCP):
        detect_rogue_dhcp(packet)

    try:
        if IP in packet:
            source_ip = packet[IP].src
            source_mac = packet[Ether].src.upper() if Ether in packet else "unknown"

            # Passive OS fingerprint observation: capture TTL + TCP window
            if TCP in packet:
                with data_lock:
                    prev = observed_tcp.get(source_ip, {})
                    prev["ttl"] = packet[IP].ttl
                    prev["window"] = packet[TCP].window
                    prev["last_seen"] = time.time()
                    observed_tcp[source_ip] = prev
                    # Bound: drop entries not seen for over an hour
                    if len(observed_tcp) > 500:
                        stale = [k for k, v in observed_tcp.items()
                                 if time.time() - v.get("last_seen", 0) > 3600]
                        for k in stale[:100]:
                            observed_tcp.pop(k, None)

            # DHCP hostname observation (option 12)
            if DHCP in packet:
                try:
                    for opt in packet[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "hostname":
                            with data_lock:
                                entry = observed_tcp.setdefault(source_ip, {})
                                entry["dhcp_hostname"] = opt[1].decode("utf-8", errors="ignore")
                            break
                except Exception:
                    pass

            # Per-device traffic estimation
            if source_mac != "unknown":
                with data_lock:
                    info = per_device_traffic.get(source_mac, {"bytes": 0, "packets": 0, "last_seen": 0})
                    info["bytes"] += len(packet)
                    info["packets"] += 1
                    info["last_seen"] = datetime.now().isoformat()
                    per_device_traffic[source_mac] = info
                # Bound the dict size
                if len(per_device_traffic) > 300:
                    with data_lock:
                        oldest = min(per_device_traffic, key=lambda k: per_device_traffic[k]["last_seen"])
                        per_device_traffic.pop(oldest, None)

            # Live traffic viewer - log HTTP hostnames and DNS queries
            traffic_entry = None

            # Extract HTTP Host header
            if TCP in packet and Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'Host:' in payload or 'HTTP' in payload:
                        lines = payload.split('\r\n')
                        for line in lines:
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                                traffic_entry = {
                                    "timestamp": datetime.now().isoformat(),
                                    "type": "HTTP",
                                    "source_ip": source_ip,
                                    "source_mac": source_mac,
                                    "domain": host,
                                    "details": f"HTTP request to {host}"
                                }
                                break
                except:
                    pass

            # Process DNS queries (also adds to live traffic)
            if DNS in packet and DNSQR in packet:
                process_dns_query(packet, source_ip, source_mac)
                query_name = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                traffic_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "DNS",
                    "source_ip": source_ip,
                    "source_mac": source_mac,
                    "domain": query_name,
                    "details": f"DNS query: {query_name}"
                }
                # DNS spoof rule match -> respond with fake IP (educational lab)
                if DNS_SPOOF_RULES:
                    with data_lock:
                        rule_domain = query_name.lower()
                    if rule_domain in DNS_SPOOF_RULES:
                        try:
                            dns_server_ip = packet[IP].dst
                            fake_ip = spoof_dns_response(packet, query_name, dns_server_ip)
                            traffic_entry["details"] += f" [SPOOFED -> {fake_ip}]"
                        except Exception as e:
                            print(f"[!] DNS spoof error: {e}")

            # Extract SNI from TLS ClientHello (HTTPS domains without decryption)
            if TLS in packet or (TCP in packet and Raw in packet):
                try:
                    sni = extract_sni(packet)
                    if sni:
                        traffic_entry = {
                            "timestamp": datetime.now().isoformat(),
                            "type": "TLS_SNI",
                            "source_ip": source_ip,
                            "source_mac": source_mac,
                            "domain": sni,
                            "details": f"HTTPS connection to {sni} (from SNI)"
                        }
                except Exception:
                    pass

            # Add to live traffic if we have an entry
            if traffic_entry:
                with data_lock:
                    live_traffic.append(traffic_entry)
                    if len(live_traffic) > LIVE_TRAFFIC_LIMIT:
                        live_traffic = live_traffic[-LIVE_TRAFFIC_LIMIT:]

            packet_info = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": source_ip,
                "dst_ip": packet[IP].dst,
                "protocol": packet[IP].proto,
                "length": len(packet),
            }

            # Add protocol-specific info
            if TCP in packet:
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                packet_info["protocol_name"] = "TCP"
                packet_info["flags"] = str(packet[TCP].flags)
            elif UDP in packet:
                packet_info["src_port"] = packet[UDP].sport
                packet_info["dst_port"] = packet[UDP].dport
                packet_info["protocol_name"] = "UDP"
            elif ICMP in packet:
                packet_info["protocol_name"] = "ICMP"
                packet_info["icmp_type"] = packet[ICMP].type
                packet_info["icmp_code"] = packet[ICMP].code
            else:
                packet_info["protocol_name"] = "OTHER"

            # Detect MITM attacks
            detect_mitm(packet)

            # Process TLS fingerprints (JA3)
            if TCP in packet and Raw in packet:
                process_tls_fingerprint(packet, source_ip, source_mac)

            # Keep only last 1000 packets to avoid memory issues
            with data_lock:
                captured_packets.append(packet_info)
                if len(captured_packets) > 1000:
                    captured_packets = captured_packets[-1000:]
    except Exception as e:
        print(f"[!] Error processing packet: {e}")


# ============================================================
# ROGUE DHCP DETECTOR
# ============================================================
def detect_rogue_dhcp(packet):
    """Detect rogue DHCP servers by monitoring DHCP Offer packets."""
    global ROGUE_DHCP_ALERTS
    
    try:
        if not packet.haslayer(DHCP):
            return
        
        dhcp_options = packet[DHCP].options
        message_type = None
        server_id = None
        
        for opt in dhcp_options:
            if isinstance(opt, tuple):
                if opt[0] == 'message-type':
                    message_type = opt[1]
                elif opt[0] == 'server_id':
                    server_id = opt[1]
        
        # DHCP Offer (type 2) or DHCP ACK (type 5) from unexpected server
        if message_type in [2, 5]:  # OFFER or ACK
            # Get the actual sender MAC/IP
            if Ether not in packet or IP not in packet:
                return
            
            sender_mac = packet[Ether].src.upper()
            sender_ip = packet[IP].src
            
            # Check if this is from our legitimate gateway
            gateway_ip = get_default_gateway()
            
            # If not from gateway, it's a rogue DHCP server!
            if sender_ip != gateway_ip and server_id != gateway_ip:
                alert_msg = f"Rogue DHCP Server detected! MAC: {sender_mac}, IP: {sender_ip}, pretending to offer: {server_id}"
                
                rogure_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "rogue_mac": sender_mac,
                    "rogue_ip": sender_ip,
                    "offered_server": server_id,
                    "message_type": "DHCP_OFFER" if message_type == 2 else "DHCP_ACK"
                }
                
                with data_lock:
                    ROGUE_DHCP_ALERTS.append(rogure_entry)
                    if len(ROGUE_DHCP_ALERTS) > 50:
                        ROGUE_DHCP_ALERTS = ROGUE_DHCP_ALERTS[-50:]
                
                generate_alert("rogue_dhcp", alert_msg, sender_mac)
                print(f"[!] ROGUE DHCP SERVER DETECTED: {alert_msg}")
                
                # Log to audit
                conn = get_db()
                conn.execute("""
                    INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, details, success)
                    VALUES (?, 'rogue_dhcp_detected', ?, ?, ?, 1)
                """, (datetime.now().isoformat(), sender_mac, sender_ip, alert_msg))
                conn.commit()
                conn.close()
                
    except Exception as e:
        print(f"[!] Rogue DHCP detection error: {e}")


def start_packet_capture(interface=None, filter_str="", count=0):
    """Start packet capture in background thread."""
    global packet_capture_active
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed"

    def capture_loop():
        global packet_capture_active
        try:
            sniff(
                iface=interface,
                filter=filter_str,
                prn=packet_handler,
                store=0,
                stop_filter=lambda x: not packet_capture_active,
                count=count,
            )
        except Exception as e:
            print(f"[!] Packet capture error: {e}")
        finally:
            packet_capture_active = False

    packet_capture_active = True
    capture_thread = threading.Thread(target=capture_loop, daemon=True)
    capture_thread.start()
    return True, "Packet capture started"


def stop_packet_capture():
    """Stop packet capture."""
    global packet_capture_active
    packet_capture_active = False
    return True, "Packet capture stopped"


def get_captured_packets(limit=100):
    """Get captured packets."""
    with data_lock:
        return captured_packets[-limit:] if captured_packets else []


def clear_captured_packets():
    """Clear captured packets."""
    global captured_packets
    with data_lock:
        captured_packets = []
    return True, "Cleared captured packets"


# ============================================================
# NETWORK MESSAGING
# ============================================================
def send_network_message(target_ip, message):
    """Send a message to a device on the network."""
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(["msg", "*", f"/SERVER:{target_ip}", message], timeout=5)
            return True, "Message sent"
        elif system == "Linux":
            # Try smbclient for Windows targets
            subprocess.run(
                ["smbclient", "-M", target_ip, "-U", "%"],
                input=message.encode(),
                timeout=5,
                capture_output=True,
            )
            return True, "Message sent (via SMB)"
        return False, "Messaging not supported on this OS"
    except FileNotFoundError:
        return False, "Required tool (smbclient/msg) not installed"
    except Exception as e:
        return False, str(e)


# ============================================================
# SPEED TEST
# ============================================================
def run_speed_test():
    """Run internet speed test."""
    if not SPEEDTEST_AVAILABLE:
        return {"error": "speedtest-cli not installed. Run: pip install speedtest-cli"}
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download = st.download() / 1_000_000  # Mbps
        upload = st.upload() / 1_000_000
        ping = st.results.ping
        server = st.results.server
        return {
            "download": round(download, 2),
            "upload": round(upload, 2),
            "ping": round(ping, 2),
            "server": server.get("sponsor", "Unknown"),
            "server_location": f"{server.get('name', '')}, {server.get('country', '')}",
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# BACKGROUND SCANNER
# ============================================================
scanner_running = False


def background_scanner():
    """Background thread that periodically scans the network."""
    global scanner_running
    scanner_running = True
    last_prune = 0
    
    # Start the scan queue worker
    worker_thread = threading.Thread(target=scan_worker, daemon=True)
    worker_thread.start()
    
    while scanner_running:
        try:
            start = time.time()
            devices = arp_scan()
            new_count = update_devices_db(devices)
            duration = time.time() - start
            # Log scan
            conn = get_db()
            conn.execute(
                """
                INSERT INTO scan_log (timestamp, devices_found, new_devices, scan_duration)
                VALUES (?, ?, ?, ?)
            """,
                (
                    datetime.now().isoformat(),
                    len(devices),
                    new_count,
                    round(duration, 2),
                ),
            )
            conn.commit()
            conn.close()
            log_bandwidth()
            print(
                f"[*] Scan complete: {len(devices)} devices found, {new_count} new ({duration:.1f}s)"
            )

            # Check for security events and log them
            check_security_events(devices)

            # Prune old data roughly every 6 hours
            if time.time() - last_prune > 6 * 3600:
                prune_old_data()
                last_prune = time.time()
        except Exception as e:
            print(f"[!] Scan error: {e}")
        time.sleep(SCAN_INTERVAL)


def check_security_events(devices):
    """Check for security-related events during scanning."""
    conn = get_db()
    c = conn.cursor()

    for dev in devices:
        # Check for new devices
        existing = c.execute(
            "SELECT * FROM devices WHERE mac = ?", (dev["mac"],)
        ).fetchone()
        if not existing:
            # New device detected - already handled in update_devices_db
            pass
        else:
            # Check for IP changes (possible ARP spoofing)
            if existing["ip"] != dev["ip"]:
                c.execute(
                    """
                    INSERT INTO alerts (timestamp, alert_type, message, device_mac)
                    VALUES (?, 'ip_change', ?, ?)
                """,
                    (
                        datetime.now().isoformat(),
                        f"IP address changed for {dev['mac']}: {existing['ip']} -> {dev['ip']}",
                        dev["mac"],
                    ),
                )

            # Check for MAC address changes (possible MAC spoofing)
            if existing["mac"] != dev["mac"]:
                c.execute(
                    """
                    INSERT INTO alerts (timestamp, alert_type, message, device_mac)
                    VALUES (?, 'mac_change', ?, ?)
                """,
                    (
                        datetime.now().isoformat(),
                        f"MAC address changed for {existing['ip']}: {existing['mac']} -> {dev['mac']}",
                        dev["mac"],
                    ),
                )

    conn.commit()
    conn.close()


def generate_security_report():
    """Generate a security report based on collected data."""
    conn = get_db()
    conn.row_factory = sqlite3.Row

    # Get basic stats
    total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online_devices = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE is_online = 1"
    ).fetchone()[0]
    blocked_devices = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE is_blocked = 1"
    ).fetchone()[0]
    unknown_devices = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE is_known = 0"
    ).fetchone()[0]

    # Get recent alerts
    recent_alerts = conn.execute("""
        SELECT * FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT 20
    """).fetchall()

    # Get devices with potential issues
    suspicious_devices = conn.execute("""
        SELECT * FROM devices 
        WHERE is_blocked = 1 OR is_known = 0
        ORDER BY last_seen DESC
    """).fetchall()

    conn.close()

    return {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_devices": total_devices,
            "online_devices": online_devices,
            "blocked_devices": blocked_devices,
            "unknown_devices": unknown_devices,
        },
        "recent_alerts": [dict(alert) for alert in recent_alerts],
        "suspicious_devices": [dict(device) for device in suspicious_devices],
    }


# ============================================================
# PARENTAL CONTROL ENFORCER
# ============================================================
def _rule_applies_today(rule_day, weekday):
    if rule_day == "everyday":
        return True
    if rule_day == "weekdays":
        return weekday in ("monday", "tuesday", "wednesday", "thursday", "friday")
    if rule_day == "weekends":
        return weekday in ("saturday", "sunday")
    return rule_day == weekday


def _time_in_window(now, start_time, end_time):
    """Check if now falls inside [start, end], supporting overnight windows."""
    try:
        start_parts = list(map(int, start_time.split(":")))
        end_parts = list(map(int, end_time.split(":")))
        start_min = start_parts[0] * 60 + start_parts[1]
        end_min = end_parts[0] * 60 + end_parts[1]
        now_min = now.hour * 60 + now.minute
    except (ValueError, IndexError):
        return False
    if start_min <= end_min:
        return start_min <= now_min <= end_min
    # Overnight window (e.g. 22:00 -> 07:00)
    return now_min >= start_min or now_min <= end_min


def parental_enforcer():
    """Background thread that actually enforces parental schedule rules."""
    global scheduler_blocked
    while scanner_running:
        try:
            now = datetime.now()
            weekday = now.strftime("%A").lower()

            conn = get_db()
            rules = conn.execute("SELECT * FROM parental_rules").fetchall()
            conn.close()

            gateway = get_default_gateway()
            to_block, to_unblock = [], []
            for rule in rules:
                if rule["action"] != "block":
                    continue
                if not _rule_applies_today(rule["day_of_week"], weekday):
                    continue
                if _time_in_window(now, rule["start_time"], rule["end_time"]):
                    to_block.append(rule["device_mac"])
                else:
                    to_unblock.append(rule["device_mac"])

            conn = get_db()
            for mac in set(to_block):
                if mac in scheduler_blocked:
                    continue
                device = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
                if not device:
                    continue
                success, msg = block_device(device["ip"], gateway)
                if success:
                    scheduler_blocked.add(mac)
                    conn.execute("UPDATE devices SET is_blocked = 1 WHERE mac = ?", (mac,))
                    conn.execute(
                        "INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, user, details, success) "
                        "VALUES (?, 'parental_block', ?, ?, 'scheduler', ?, 1)",
                        (now.isoformat(), mac, device["ip"], msg),
                    )
                    generate_alert("parental_block", f"Parental rule: blocked {device['ip']}", mac)

            for mac in set(to_unblock):
                if mac not in scheduler_blocked:
                    continue
                device = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
                if not device:
                    continue
                success, msg = unblock_device(device["ip"], gateway)
                if success:
                    scheduler_blocked.discard(mac)
                    conn.execute("UPDATE devices SET is_blocked = 0 WHERE mac = ?", (mac,))
                    conn.execute(
                        "INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, user, details, success) "
                        "VALUES (?, 'parental_unblock', ?, ?, 'scheduler', ?, 1)",
                        (now.isoformat(), mac, device["ip"], msg),
                    )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] Parental enforcer error: {e}")
        time.sleep(30)


def prune_old_data():
    """Remove old logs to keep the database small (runs ~every 6 hours)."""
    try:
        conn = get_db()
        cutoffs = {
            "alerts": timedelta(days=int(os.environ.get("RETAIN_ALERTS_DAYS", "30"))),
            "audit_log": timedelta(days=int(os.environ.get("RETAIN_AUDIT_DAYS", "90"))),
            "dns_query_log": timedelta(days=int(os.environ.get("RETAIN_DNS_DAYS", "14"))),
            "passive_dns_log": timedelta(days=int(os.environ.get("RETAIN_DNS_DAYS", "14"))),
            "bandwidth_log": timedelta(days=int(os.environ.get("RETAIN_BW_DAYS", "7"))),
            "ja3_log": timedelta(days=int(os.environ.get("RETAIN_JA3_DAYS", "30"))),
            "port_scan_history": timedelta(days=int(os.environ.get("RETAIN_PORT_DAYS", "90"))),
        }
        for table, days in cutoffs.items():
            cutoff = (datetime.now() - days).isoformat()
            conn.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
        print("[*] Old data pruned")
    except Exception as e:
        print(f"[!] Prune error: {e}")


def cleanup_network_actions():
    """On shutdown: stop packet capture, restore ARP tables for all
    blocked devices and MITM targets so the network is left clean."""
    global scanner_running, blocking_threads, active_mitm_attacks
    scanner_running = False
    stop_packet_capture()

    gateway = get_default_gateway()
    for ip in list(blocking_threads.keys()):
        try:
            unblock_device(ip, gateway)
        except Exception:
            pass
    for ip in list(active_mitm_attacks.keys()):
        try:
            stop_mitm_attack(ip)
        except Exception:
            pass
    time.sleep(1)
    print("[*] Network actions cleaned up (ARP tables restored)")


# ============================================================
# API ROUTES
# ============================================================


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page with brute-force lockout and CSRF protection."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"

        # Brute-force lockout: max 5 failed attempts per 15 minutes per IP
        now = time.time()
        login_attempts[client_ip] = [
            t for t in login_attempts[client_ip] if now - t < LOGIN_ATTEMPT_WINDOW
        ]
        if len(login_attempts[client_ip]) >= LOGIN_ATTEMPT_LIMIT:
            flash(
                "Too many failed login attempts. Please wait 15 minutes.",
                "error",
            )
            return render_template("login.html")

        if username == DEFAULT_USERNAME and check_password_hash(
            ADMIN_PASSWORD_HASH, password
        ):
            login_attempts[client_ip] = []
            user = User(username)
            login_user(user)
            flash("Logged in successfully!", "success")
            # Only allow safe relative redirects (fixes open-redirect)
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/") and not next_page.startswith("//"):
                return redirect(next_page)
            return redirect(url_for("dashboard"))
        else:
            login_attempts[client_ip].append(now)
            flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Logout endpoint."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    """Trigger a manual network scan (rate limited)."""
    client_ip = request.remote_addr
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "Rate limit exceeded. Please wait."}), 429

    start = time.time()
    devices = arp_scan()
    new_count = update_devices_db(devices)
    duration = time.time() - start
    record_scan(client_ip)
    
    # Log the scan action
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, user, details, success)
        VALUES (?, 'manual_scan', ?, ?, 1)
    """,
        (datetime.now().isoformat(), current_user.username, f"Scan completed in {duration:.2f}s"),
    )
    conn.commit()
    conn.close()
    
    return jsonify(
        {
            "success": True,
            "devices_found": len(devices),
            "new_devices": new_count,
            "duration": round(duration, 2),
        }
    )


@app.route("/api/devices")
@login_required
def api_devices():
    """Get all known devices with OS fingerprint info."""
    conn = get_db()
    devices = conn.execute(
        "SELECT * FROM devices ORDER BY is_online DESC, last_seen DESC"
    ).fetchall()
    
    # Enrich with OS fingerprint data if available
    device_list = []
    for d in devices:
        dev_dict = dict(d)
        os_info = conn.execute(
            "SELECT os_guess, confidence FROM os_fingerprint_log WHERE device_mac = ?",
            (d["mac"],)
        ).fetchone()
        if os_info:
            dev_dict["os_guess"] = os_info["os_guess"]
            dev_dict["os_confidence"] = os_info["confidence"]
        else:
            dev_dict["os_guess"] = None
            dev_dict["os_confidence"] = 0
        # Attach traffic estimate if observed
        with data_lock:
            traffic = per_device_traffic.get(d["mac"])
        dev_dict["traffic_bytes"] = traffic["bytes"] if traffic else None
        dev_dict["traffic_packets"] = traffic["packets"] if traffic else None
        device_list.append(dev_dict)
    
    conn.close()
    return jsonify(device_list)


@app.route("/api/devices/<mac>", methods=["PUT"])
@login_required
def api_update_device(mac):
    """Update device info (custom name, type, notes, known status)."""
    data = get_json_body()
    conn = get_db()
    fields = []
    values = []
    valid_types = {
        "unknown", "phone", "tablet", "laptop", "desktop", "tv", "printer",
        "smart_speaker", "camera", "iot", "router", "other",
    }
    for key in ["custom_name", "device_type", "notes", "is_known"]:
        if key in data:
            if key == "device_type" and data[key] not in valid_types:
                continue
            if key == "is_known":
                try:
                    data[key] = int(data[key])
                except (TypeError, ValueError):
                    continue
            if key in ("custom_name", "notes"):
                data[key] = str(data[key])[:200]
            fields.append(f"{key} = ?")
            values.append(data[key])
    if fields:
        values.append(mac)
        conn.execute(f"UPDATE devices SET {', '.join(fields)} WHERE mac = ?", values)
        conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/devices/<mac>/block", methods=["POST"])
@login_required
def api_block_device(mac):
    """Block a device - with audit logging."""
    client_ip = request.remote_addr
    
    # Check rate limit
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "Rate limit exceeded. Please wait."}), 429
    
    record_scan(client_ip)
    
    conn = get_db()
    device = conn.execute("SELECT ip, hostname FROM devices WHERE mac = ?", (mac,)).fetchone()
    if not device:
        conn.close()
        return jsonify({"success": False, "error": "Device not found"}), 404

    gateway = get_default_gateway()
    success, msg = block_device(device["ip"], gateway)
    
    # AUDIT LOG - always log block attempts
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, user, details, success)
        VALUES (?, 'block_device', ?, ?, ?, ?, ?)
    """,
        (datetime.now().isoformat(), mac, device["ip"], current_user.username, msg, 1 if success else 0),
    )
    
    if success:
        conn.execute("UPDATE devices SET is_blocked = 1 WHERE mac = ?", (mac,))
        conn.execute(
            """
            INSERT INTO alerts (timestamp, alert_type, message, device_mac)
            VALUES (?, 'device_blocked', ?, ?)
        """,
            (datetime.now().isoformat(), f"Device {device['ip']} blocked", mac),
        )
    conn.commit()
    conn.close()
    return jsonify({"success": success, "message": msg})


@app.route("/api/devices/<mac>/unblock", methods=["POST"])
@login_required
def api_unblock_device(mac):
    """Unblock a device - with audit logging."""
    client_ip = request.remote_addr
    
    # Check rate limit
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "Rate limit exceeded. Please wait."}), 429
    
    record_scan(client_ip)
    
    conn = get_db()
    device = conn.execute("SELECT ip, hostname FROM devices WHERE mac = ?", (mac,)).fetchone()
    if not device:
        conn.close()
        return jsonify({"success": False, "error": "Device not found"}), 404

    gateway = get_default_gateway()
    success, msg = unblock_device(device["ip"], gateway)
    
    # AUDIT LOG - always log unblock attempts
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, user, details, success)
        VALUES (?, 'unblock_device', ?, ?, ?, ?, ?)
    """,
        (datetime.now().isoformat(), mac, device["ip"], current_user.username, msg, 1 if success else 0),
    )
    
    if success:
        conn.execute("UPDATE devices SET is_blocked = 0 WHERE mac = ?", (mac,))
    conn.commit()
    conn.close()
    return jsonify({"success": success, "message": msg})


@app.route("/api/devices/<mac>/message", methods=["POST"])
@login_required
def api_send_message(mac):
    """Send a message to a device (authentication required)."""
    data = get_json_body()
    message = str(data.get("message", ""))[:500]
    if not message:
        return jsonify({"success": False, "error": "No message provided"}), 400

    conn = get_db()
    device = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    success, msg = send_network_message(device["ip"], message)
    return jsonify({"success": success, "message": msg})


@app.route("/api/devices/<mac>/portscan", methods=["POST"])
@login_required
def api_port_scan(mac):
    """Run a port scan on a device - with rate limiting and queue."""
    client_ip = request.remote_addr
    
    # Check rate limit for scans
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "Rate limit exceeded. Please wait."}), 429
    
    data = get_json_body()
    port_range = str(data.get("range", "1-1024"))

    # Validate port range format and bounds
    match = re.match(r"^(\d{1,5})-(\d{1,5})$", port_range)
    if not match:
        return jsonify({"success": False, "error": "Invalid port range. Use format start-end, e.g. 1-1024"}), 400
    start_p, end_p = int(match.group(1)), int(match.group(2))
    if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p):
        return jsonify({"success": False, "error": "Port range must be between 1 and 65535"}), 400
    if (end_p - start_p) > 10000:
        return jsonify({"success": False, "error": "Port range too large (max 10000 ports)"}), 400

    conn = get_db()
    device = conn.execute("SELECT ip, mac FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    # Use queue for port scans to prevent flooding
    result_queue = queue.Queue()
    
    def do_scan():
        ports = scan_ports(device["ip"], port_range, device_mac=device["mac"])
        result_queue.put(ports)
    
    success, msg = add_scan_to_queue(do_scan)
    if not success:
        return jsonify({"success": False, "error": msg}), 503
    
    # Wait for result (with timeout)
    try:
        ports = result_queue.get(timeout=30)
        record_scan(client_ip)
        
        # Log the scan
        conn = get_db()
        conn.execute(
            """
            INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, user, details, success)
            VALUES (?, 'port_scan', ?, ?, ?, ?, 1)
        """,
            (datetime.now().isoformat(), mac, device["ip"], current_user.username, f"Port range: {port_range}"),
        )
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "ip": device["ip"], "ports": ports})
    except queue.Empty:
        return jsonify({"success": False, "error": "Scan timed out"}), 504


@app.route("/api/devices/<mac>/fingerprint", methods=["POST"])
@login_required
def api_device_fingerprint(mac):
    """Actively fingerprint a device's OS (TCP SYN probe for TTL + window)."""
    client_ip = request.remote_addr
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "Rate limit exceeded. Please wait."}), 429

    conn = get_db()
    device = conn.execute("SELECT ip, mac, vendor FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    if not SCAPY_AVAILABLE:
        return jsonify({"success": False, "error": "Scapy not installed - cannot probe"}), 400

    record_scan(client_ip)
    result = active_os_fingerprint(device["ip"])
    if not result:
        return jsonify({"success": False, "error": "Device did not respond to probe"}), 408

    # Save the result
    conn = get_db()
    save_os_fingerprint(conn, device["mac"], device["ip"], device["vendor"] or "Unknown")
    os_row = conn.execute(
        "SELECT os_guess, confidence FROM os_fingerprint_log WHERE device_mac = ?",
        (device["mac"],),
    ).fetchone()
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "ip": device["ip"],
        "ttl": result["ttl"],
        "tcp_window_size": result["tcp_window_size"],
        "os_guess": os_row["os_guess"] if os_row else "Unknown",
        "os_confidence": os_row["confidence"] if os_row else 0,
    })


@app.route("/api/devices/<mac>/vulnscan", methods=["POST"])
@login_required
def api_vulnerability_scan(mac):
    """Run a vulnerability scan on a device - with rate limiting."""
    client_ip = request.remote_addr
    
    # Check rate limit
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "Rate limit exceeded. Please wait."}), 429
    
    conn = get_db()
    device = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    record_scan(client_ip)
    vulnerabilities = vulnerability_scan(device["ip"])
    
    # Log the scan
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, device_mac, device_ip, user, details, success)
        VALUES (?, 'vuln_scan', ?, ?, ?, ?, 1)
    """,
        (datetime.now().isoformat(), mac, device["ip"], current_user.username, f"Found {len(vulnerabilities)} issues"),
    )
    conn.commit()
    conn.close()
    
    return jsonify(
        {"success": True, "ip": device["ip"], "vulnerabilities": vulnerabilities}
    )


@app.route("/api/wifi")
@login_required
def api_wifi():
    """Get WiFi information."""
    return jsonify(get_wifi_info())


@app.route("/api/wifi/security")
@login_required
def api_wifi_security():
    """Get WiFi security information."""
    wifi_info = get_wifi_info()
    security_info = wifi_security_scan(wifi_info)
    return jsonify({"wifi": wifi_info, "security": security_info})


@app.route("/api/bandwidth")
@login_required
def api_bandwidth():
    """Get current bandwidth usage."""
    return jsonify(get_bandwidth())


@app.route("/api/speedtest", methods=["POST"])
@login_required
def api_speedtest():
    """Run speed test."""
    result = run_speed_test()
    
    # Log the action
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, user, details, success)
        VALUES (?, 'speedtest', ?, ?, 1)
    """,
        (datetime.now().isoformat(), current_user.username, "Speed test completed"),
    )
    conn.commit()
    conn.close()
    
    return jsonify(result)


@app.route("/api/packet-capture/start", methods=["POST"])
@login_required
def api_start_packet_capture():
    """Start packet capture."""
    data = get_json_body()
    interface = str(data.get("interface") or "") or None
    filter_str = str(data.get("filter") or "")[:200]
    try:
        count = int(data.get("count", 0))
        count = max(0, min(count, 1_000_000))
    except (TypeError, ValueError):
        count = 0

    success, message = start_packet_capture(interface, filter_str, count)
    
    # Log the action
    if success:
        conn = get_db()
        conn.execute(
            """
            INSERT INTO audit_log (timestamp, action_type, user, details, success)
            VALUES (?, 'packet_capture_start', ?, ?, 1)
        """,
            (datetime.now().isoformat(), current_user.username, f"Interface: {interface}, Filter: {filter_str}"),
        )
        conn.commit()
        conn.close()
    
    return jsonify({"success": success, "message": message})


@app.route("/api/packet-capture/stop", methods=["POST"])
@login_required
def api_stop_packet_capture():
    """Stop packet capture."""
    success, message = stop_packet_capture()
    
    # Log the action
    if success:
        conn = get_db()
        conn.execute(
            """
            INSERT INTO audit_log (timestamp, action_type, user, details, success)
            VALUES (?, 'packet_capture_stop', ?, ?, 1)
        """,
            (datetime.now().isoformat(), current_user.username, "Packet capture stopped"),
        )
        conn.commit()
        conn.close()
    
    return jsonify({"success": success, "message": message})


@app.route("/api/packet-capture/clear", methods=["POST"])
@login_required
def api_clear_packet_capture():
    """Clear captured packets."""
    success, message = clear_captured_packets()
    return jsonify({"success": success, "message": message})


@app.route("/api/packet-capture/data")
@login_required
def api_get_packet_capture_data():
    """Get captured packet data."""
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    packets = get_captured_packets(limit)
    return jsonify({"packets": packets, "count": len(packets)})


@app.route("/api/alerts")
@login_required
def api_alerts():
    """Get alerts."""
    conn = get_db()
    limit = min(max(request.args.get("limit", 50, type=int), 1), 500)
    alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return jsonify([dict(a) for a in alerts])


@app.route("/api/alerts/read", methods=["POST"])
@login_required
def api_mark_alerts_read():
    """Mark all alerts as read."""
    conn = get_db()
    conn.execute("UPDATE alerts SET is_read = 1")
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/audit-log")
@login_required
def api_audit_log():
    """Get audit log entries."""
    conn = get_db()
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    action_type = request.args.get("action_type")
    
    if action_type:
        entries = conn.execute(
            "SELECT * FROM audit_log WHERE action_type = ? ORDER BY timestamp DESC LIMIT ?",
            (action_type, limit)
        ).fetchall()
    else:
        entries = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return jsonify([dict(e) for e in entries])


@app.route("/api/dns-queries")
@login_required
def api_dns_queries():
    """Get DNS query log with threat scoring."""
    conn = get_db()
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    min_threat = max(request.args.get("min_threat", 0, type=int), 0)
    
    if min_threat > 0:
        queries = conn.execute(
            "SELECT * FROM dns_query_log WHERE threat_score >= ? ORDER BY timestamp DESC LIMIT ?",
            (min_threat, limit)
        ).fetchall()
    else:
        queries = conn.execute(
            "SELECT * FROM dns_query_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return jsonify([dict(q) for q in queries])


@app.route("/api/passive-dns")
@login_required
def api_passive_dns():
    """Get passive DNS log - top domains per device."""
    conn = get_db()
    mac = request.args.get("mac")
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    
    if mac:
        # Get top domains for specific device
        results = conn.execute("""
            SELECT domain, SUM(visit_count) as total_visits, MAX(timestamp) as last_seen
            FROM passive_dns_log 
            WHERE source_mac = ?
            GROUP BY domain
            ORDER BY total_visits DESC
            LIMIT ?
        """, (mac, limit)).fetchall()
    else:
        # Get overall top domains
        results = conn.execute("""
            SELECT domain, source_mac, SUM(visit_count) as total_visits, MAX(timestamp) as last_seen
            FROM passive_dns_log 
            GROUP BY domain, source_mac
            ORDER BY total_visits DESC
            LIMIT ?
        """, (limit,)).fetchall()
    
    conn.close()
    return jsonify([dict(r) for r in results])


@app.route("/api/port-history")
@login_required
def api_port_history():
    """Get port scan history for a device or all devices."""
    conn = get_db()
    mac = request.args.get("mac")
    new_only = request.args.get("new_only", "false").lower() == "true"
    limit = min(max(request.args.get("limit", 200, type=int), 1), 500)
    
    if mac:
        if new_only:
            results = conn.execute("""
                SELECT * FROM port_scan_history 
                WHERE device_mac = ? AND is_new = 1
                ORDER BY first_seen DESC
                LIMIT ?
            """, (mac, limit)).fetchall()
        else:
            results = conn.execute("""
                SELECT * FROM port_scan_history 
                WHERE device_mac = ?
                ORDER BY last_seen DESC
                LIMIT ?
            """, (mac, limit)).fetchall()
    else:
        # All devices, showing most recent
        results = conn.execute("""
            SELECT * FROM port_scan_history 
            ORDER BY last_seen DESC
            LIMIT ?
        """, (limit,)).fetchall()
    
    conn.close()
    return jsonify([dict(r) for r in results])


@app.route("/api/ja3-fingerprints")
@login_required
def api_ja3_fingerprints():
    """Get JA3 fingerprint log."""
    conn = get_db()
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    suspicious_only = request.args.get("suspicious", "false").lower() == "true"
    
    if suspicious_only:
        fingerprints = conn.execute(
            "SELECT * FROM ja3_log WHERE is_suspicious = 1 ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    else:
        fingerprints = conn.execute(
            "SELECT * FROM ja3_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return jsonify([dict(f) for f in fingerprints])


@app.route("/api/mitm-alerts")
@login_required
def api_mitm_alerts():
    """Get MITM/ARP spoofing alerts."""
    global MITM_ALERTS
    limit = min(max(request.args.get("limit", 50, type=int), 1), 500)
    with data_lock:
        return jsonify(MITM_ALERTS[-limit:] if MITM_ALERTS else [])


@app.route("/api/rogue-dhcp-alerts")
@login_required
def api_rogue_dhcp_alerts():
    """Get Rogue DHCP server alerts."""
    global ROGUE_DHCP_ALERTS
    limit = min(max(request.args.get("limit", 50, type=int), 1), 500)
    with data_lock:
        return jsonify(ROGUE_DHCP_ALERTS[-limit:] if ROGUE_DHCP_ALERTS else [])


@app.route("/api/live-traffic")
@login_required
def api_live_traffic():
    """Get live traffic viewer data (HTTP hostnames, DNS queries, TLS SNI)."""
    global live_traffic
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    with data_lock:
        return jsonify(live_traffic[-limit:] if live_traffic else [])


@app.route("/api/traffic-summary")
@login_required
def api_traffic_summary():
    """Get per-device traffic estimates collected from captured packets."""
    global per_device_traffic
    with data_lock:
        summary = [
            {"mac": mac, "bytes": info["bytes"], "packets": info["packets"],
             "last_seen": info["last_seen"]}
            for mac, info in per_device_traffic.items()
        ]
    summary.sort(key=lambda x: x["bytes"], reverse=True)
    return jsonify(summary)


@app.route("/api/active-mitm", methods=["GET"])
@login_required
def api_get_active_mitm():
    """Get list of currently active MITM attacks."""
    return jsonify(get_active_mitm_attacks())


@app.route("/api/devices/<mac>/start-mitm", methods=["POST"])
@login_required
def api_start_mitm(mac):
    """Start MITM attack simulation on a device (educational)."""
    conn = get_db()
    device = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404
    
    data = get_json_body()
    enable_dns_spoof = bool(data.get("dns_spoof", False))
    fake_ip = data.get("fake_ip")
    if fake_ip is not None:
        try:
            ipaddress.ip_address(str(fake_ip))
        except ValueError:
            return jsonify({"success": False, "error": "Invalid fake_ip"}), 400
    
    success, msg = start_mitm_attack(device["ip"], enable_dns_spoof, fake_ip)
    return jsonify({"success": success, "message": msg})


@app.route("/api/devices/<mac>/stop-mitm", methods=["POST"])
@login_required
def api_stop_mitm(mac):
    """Stop MITM attack simulation on a device."""
    conn = get_db()
    device = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404
    
    success, msg = stop_mitm_attack(device["ip"])
    return jsonify({"success": success, "message": msg})


@app.route("/api/dns-spoof-rules", methods=["GET"])
@login_required
def api_get_dns_spoof_rules():
    """Get all active DNS spoof rules."""
    return jsonify(get_dns_spoof_rules())


@app.route("/api/dns-spoof-rules", methods=["POST"])
@login_required
def api_add_dns_spoof_rule():
    """Add a DNS spoof rule for phishing lab simulation."""
    data = get_json_body()
    domain = str(data.get("domain", "")).strip().lower()[:255]
    fake_ip = str(data.get("fake_ip", "")).strip()

    if not domain or not fake_ip:
        return jsonify({"success": False, "error": "Domain and fake_ip required"}), 400
    if not re.match(r"^[a-z0-9\-\.]+$", domain):
        return jsonify({"success": False, "error": "Invalid domain"}), 400
    try:
        ipaddress.ip_address(fake_ip)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid fake_ip"}), 400

    success, msg = add_dns_spoof_rule(domain, fake_ip)
    return jsonify({"success": success, "message": msg})


@app.route("/api/dns-spoof-rules/<domain>", methods=["DELETE"])
@login_required
def api_delete_dns_spoof_rule(domain):
    """Remove a DNS spoof rule."""
    success, msg = remove_dns_spoof_rule(domain)
    return jsonify({"success": success, "message": msg})


@app.route("/api/stats")
@login_required
def api_stats():
    """Get dashboard statistics."""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE is_online = 1"
    ).fetchone()[0]
    blocked = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE is_blocked = 1"
    ).fetchone()[0]
    unknown = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE is_known = 0"
    ).fetchone()[0]
    unread = conn.execute("SELECT COUNT(*) FROM alerts WHERE is_read = 0").fetchone()[0]
    last_scan = conn.execute(
        "SELECT * FROM scan_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    return jsonify(
        {
            "total_devices": total,
            "online_devices": online,
            "blocked_devices": blocked,
            "unknown_devices": unknown,
            "unread_alerts": unread,
            "gateway": get_default_gateway(),
            "local_ip": get_local_ip(),
            "network_range": get_network_range(),
            "last_scan": dict(last_scan) if last_scan else None,
            "platform": platform.system(),
        }
    )


@app.route("/api/network-info")
@login_required
def api_network_info():
    """Get comprehensive network info."""
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        if iface == "lo":
            continue
        info = {"ipv4": None, "ipv6": None, "mac": None}
        for addr in addrs:
            if addr.family == socket.AF_INET:
                info["ipv4"] = addr.address
                info["netmask"] = addr.netmask
            elif addr.family == socket.AF_INET6:
                info["ipv6"] = addr.address
            elif addr.family == psutil.AF_LINK:
                info["mac"] = addr.address
        if info["ipv4"] or info["mac"]:
            interfaces[iface] = info

    return jsonify(
        {
            "interfaces": interfaces,
            "gateway": get_default_gateway(),
            "hostname": socket.gethostname(),
            "wifi": get_wifi_info(),
        }
    )


@app.route("/api/parental-rules", methods=["GET"])
@login_required
def api_get_parental_rules():
    """Get parental control rules."""
    conn = get_db()
    rules = conn.execute("SELECT * FROM parental_rules").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rules])


@app.route("/api/parental-rules", methods=["POST"])
@login_required
def api_add_parental_rule():
    """Add a parental control rule."""
    data = get_json_body()
    device_mac = str(data.get("device_mac", ""))
    day_of_week = str(data.get("day_of_week", ""))
    start_time = str(data.get("start_time", ""))
    end_time = str(data.get("end_time", ""))
    action = str(data.get("action", "block"))

    valid_days = {"everyday", "weekdays", "weekends", "monday", "tuesday",
                  "wednesday", "thursday", "friday", "saturday", "sunday"}
    if day_of_week not in valid_days:
        return jsonify({"success": False, "error": "Invalid day_of_week"}), 400
    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", start_time) or \
       not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", end_time):
        return jsonify({"success": False, "error": "Times must be HH:MM (24h)"}), 400
    if action not in ("block", "allow"):
        action = "block"

    conn = get_db()
    conn.execute(
        """
        INSERT INTO parental_rules (device_mac, day_of_week, start_time, end_time, action)
        VALUES (?, ?, ?, ?, ?)
    """,
        (device_mac, day_of_week, start_time, end_time, action),
    )
    
    # Log the action
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, user, details, success)
        VALUES (?, 'parental_rule_add', ?, ?, 1)
    """,
        (datetime.now().isoformat(), current_user.username, f"Rule for {data['device_mac']}"),
    )
    
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/parental-rules/<int:rule_id>", methods=["DELETE"])
@login_required
def api_delete_parental_rule(rule_id):
    """Delete a parental control rule."""
    conn = get_db()
    conn.execute("DELETE FROM parental_rules WHERE id = ?", (rule_id,))
    
    # Log the action
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, user, details, success)
        VALUES (?, 'parental_rule_delete', ?, ?, 1)
    """,
        (datetime.now().isoformat(), current_user.username, f"Rule ID: {rule_id}"),
    )
    
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/security-report")
@login_required
def api_security_report():
    """Generate and return a security report."""
    report = generate_security_report()
    return jsonify(report)


@app.route("/api/export/<fmt>")
@login_required
def api_export(fmt):
    """Export device list."""
    conn = get_db()
    devices = conn.execute(
        "SELECT * FROM devices ORDER BY is_online DESC, last_seen DESC"
    ).fetchall()
    conn.close()

    if fmt == "json":
        return jsonify([dict(d) for d in devices])
    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "MAC",
                "IP",
                "Hostname",
                "Vendor",
                "Type",
                "Custom Name",
                "Status",
                "First Seen",
                "Last Seen",
                "Blocked",
                "Known",
            ]
        )
        for d in devices:
            writer.writerow(
                [
                    d["mac"],
                    d["ip"],
                    d["hostname"],
                    d["vendor"],
                    d["device_type"],
                    d["custom_name"],
                    "Online" if d["is_online"] else "Offline",
                    d["first_seen"],
                    d["last_seen"],
                    "Yes" if d["is_blocked"] else "No",
                    "Yes" if d["is_known"] else "No",
                ]
            )
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=devices.csv"},
        )
    return jsonify({"error": "Invalid format"}), 400


@app.route("/api/bandwidth-history")
@login_required
def api_bandwidth_history():
    """Get bandwidth history for charts (rates computed from consecutive samples)."""
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM bandwidth_log ORDER BY timestamp ASC LIMIT 2000
    """).fetchall()
    conn.close()

    # Compute per-interface rates between consecutive samples
    by_iface = defaultdict(list)
    for r in rows:
        by_iface[r["interface"]].append(r)

    result = []
    for iface, samples in by_iface.items():
        for prev, cur in zip(samples, samples[1:]):
            try:
                dt = (
                    datetime.fromisoformat(cur["timestamp"])
                    - datetime.fromisoformat(prev["timestamp"])
                ).total_seconds()
            except (ValueError, TypeError):
                continue
            if dt <= 0:
                continue
            dl = max(0, (cur["bytes_recv"] - prev["bytes_recv"])) / dt
            ul = max(0, (cur["bytes_sent"] - prev["bytes_sent"])) / dt
            result.append(
                {
                    "timestamp": cur["timestamp"],
                    "interface": iface,
                    "download_speed": round(dl, 2),
                    "upload_speed": round(ul, 2),
                }
            )
    result = result[-200:]
    return jsonify(result)


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    banner = """
+======================================================================+
|           NETWORK ANALYZER — SECURITY AUDITING SUITE                |
|                                                                      |
|  Dashboard: http://localhost:5000                                    |
|                                                                      |
|  TIP: Run with sudo/admin for full scanning features                |
|  Press Ctrl+C to stop                                                |
|                                                                      |
|  USE ON NETWORKS YOU OWN OR HAVE PERMISSION TO TEST.                 |
+======================================================================+
    """
    print(banner)

    init_db()

    # Clean up ARP spoofing/MITM state on exit (SIGTERM, SIGINT, atexit)
    atexit.register(cleanup_network_actions)
    signal.signal(signal.SIGTERM, lambda *a: (cleanup_network_actions(), sys.exit(0)))

    # Start background scanner
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    # Start parental-control enforcer
    parental_thread = threading.Thread(target=parental_enforcer, daemon=True)
    parental_thread.start()

    # Start Flask
    try:
        app.run(host=APP_HOST, port=APP_PORT, debug=False, threaded=True)
    except KeyboardInterrupt:
        scanner_running = False
        print("\n[*] Shutting down...")
        cleanup_network_actions()
