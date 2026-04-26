#!/usr/bin/env python3
"""
Network Manager Dashboard
A real network scanner and management tool for your home WiFi.
Run with: sudo python3 network_manager.py
Dashboard: http://localhost:5000

SECURITY FEATURES:
- Authentication required (default: admin/admin123)
- Rate limiting on port scans
- Audit logging for all block/unblock actions
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
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps

from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
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
    from scapy.all import ARP, Ether, srp, send, conf, sniff, IP, TCP, UDP, ICMP, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Packet capture storage
captured_packets = []
packet_capture_active = False

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
APP_PORT = 5000
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_manager.db")
SCAN_INTERVAL = 30  # seconds between auto-scans

# Security config - CHANGE THESE IN PRODUCTION!
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production-abc123xyz")
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Rate limiting config
MAX_SCAN_QUEUE_SIZE = 10  # Max pending scans
SCAN_RATE_LIMIT = 5  # Max scans per minute per IP

# ============================================================
# FLASK APP
# ============================================================
app = Flask(__name__)
app.secret_key = SECRET_KEY

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
    conn = sqlite3.connect(DB_PATH)
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
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    """Get the network range for scanning."""
    local_ip = get_local_ip()
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

    conn.commit()
    conn.close()
    return new_count


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
                ["iwconfig"], capture_output=True, text=True, stderr=subprocess.STDOUT
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


def wifi_security_scan():
    """Perform basic WiFi security assessment."""
    security_info = {
        "encryption": "Unknown",
        "wps": "Unknown",
        "hidden_ssid": False,
        "mac_filtering": "Unknown",
        "recommendations": [],
    }

    try:
        system = platform.system()
        if system == "Linux" or system == "Darwin":
            # Try to get more detailed WiFi security info
            try:
                # Check if we can get encryption info
                result = subprocess.run(
                    ["iwlist", "auth"], capture_output=True, text=True, timeout=5
                )
                if "WPA" in result.stdout or "WPA2" in result.stdout:
                    security_info["encryption"] = "WPA/WPA2 Detected"
                elif "WEP" in result.stdout:
                    security_info["encryption"] = "WEP (WEAK)"
                    security_info["recommendations"].append(
                        "Upgrade from WEP to WPA2/WPA3"
                    )
                else:
                    security_info["encryption"] = "Open/Unknown"

                # Check for WPS
                result = subprocess.run(
                    ["iwlist", "wps"], capture_output=True, text=True, timeout=5
                )
                if "WPS" in result.stdout:
                    security_info["wps"] = "Enabled"
                    security_info["recommendations"].append(
                        "Consider disabling WPS due to security vulnerabilities"
                    )
                else:
                    security_info["wps"] = "Disabled/Unknown"

            except:
                pass

        # Add general recommendations
        if info.get("security") and "open" in info["security"].lower():
            security_info["recommendations"].append(
                "Network is open - anyone can connect"
            )
        elif info.get("security") and "wep" in info["security"].lower():
            security_info["recommendations"].append(
                "WEP encryption is weak - upgrade to WPA2/WPA3"
            )

    except Exception as e:
        print(f"[!] WiFi security scan error: {e}")

    return security_info


# ============================================================
# BANDWIDTH MONITORING
# ============================================================
prev_counters = {}


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


def log_bandwidth():
    """Log bandwidth to database."""
    counters = psutil.net_io_counters(pernic=True)
    conn = get_db()
    now = datetime.now().isoformat()
    for iface, stats in counters.items():
        if iface == "lo":
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


# ============================================================
# PORT SCANNER
# ============================================================
def scan_ports(ip, port_range="1-1024"):
    """Enhanced port scanner with service/version detection."""
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
# PACKET SNIFFING
# ============================================================
def packet_handler(packet):
    """Handle captured packets."""
    global captured_packets
    try:
        if IP in packet:
            packet_info = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": packet[IP].proto,
                "length": len(packet),
            }

            # Add protocol-specific info
            if TCP in packet:
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                packet_info["protocol_name"] = "TCP"
                packet_info["flags"] = packet[TCP].flags
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

            # Keep only last 1000 packets to avoid memory issues
            captured_packets.append(packet_info)
            if len(captured_packets) > 1000:
                captured_packets = captured_packets[-1000:]
    except Exception as e:
        print(f"[!] Error processing packet: {e}")


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
    return captured_packets[-limit:] if captured_packets else []


def clear_captured_packets():
    """Clear captured packets."""
    global captured_packets
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
# API ROUTES
# ============================================================


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
            user = User(username)
            login_user(user)
            flash("Logged in successfully!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
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
    """Trigger a manual network scan."""
    start = time.time()
    devices = arp_scan()
    new_count = update_devices_db(devices)
    duration = time.time() - start
    
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
    """Get all known devices."""
    conn = get_db()
    devices = conn.execute(
        "SELECT * FROM devices ORDER BY is_online DESC, last_seen DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(d) for d in devices])


@app.route("/api/devices/<mac>", methods=["PUT"])
@login_required
def api_update_device(mac):
    """Update device info (custom name, type, notes, known status)."""
    data = request.json
    conn = get_db()
    fields = []
    values = []
    for key in ["custom_name", "device_type", "notes", "is_known"]:
        if key in data:
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
def api_send_message(mac):
    """Send a message to a device."""
    data = request.json
    message = data.get("message", "")
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
    
    data = request.json or {}
    port_range = data.get("range", "1-1024")

    conn = get_db()
    device = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    # Use queue for port scans to prevent flooding
    result_queue = queue.Queue()
    
    def do_scan():
        ports = scan_ports(device["ip"], port_range)
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
    security_info = wifi_security_scan()
    wifi_info = get_wifi_info()
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
    data = request.json or {}
    interface = data.get("interface")
    filter_str = data.get("filter", "")
    count = data.get("count", 0)

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
    limit = request.args.get("limit", 100, type=int)
    packets = get_captured_packets(limit)
    return jsonify({"packets": packets, "count": len(packets)})


@app.route("/api/alerts")
@login_required
def api_alerts():
    """Get alerts."""
    conn = get_db()
    alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50"
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
    limit = request.args.get("limit", 100, type=int)
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
    data = request.json
    conn = get_db()
    conn.execute(
        """
        INSERT INTO parental_rules (device_mac, day_of_week, start_time, end_time, action)
        VALUES (?, ?, ?, ?, ?)
    """,
        (
            data["device_mac"],
            data["day_of_week"],
            data["start_time"],
            data["end_time"],
            data.get("action", "block"),
        ),
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
    """Get bandwidth history for charts."""
    conn = get_db()
    history = conn.execute("""
        SELECT * FROM bandwidth_log ORDER BY timestamp DESC LIMIT 100
    """).fetchall()
    conn.close()
    return jsonify([dict(h) for h in history])


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    banner = """
+======================================================================+
|           NETWORK MANAGER DASHBOARD                                  |
|                                                                      |
|  Dashboard: http://localhost:5000                                    |
|                                                                      |
|  TIP: Run with sudo/admin for full scanning features                |
|  Press Ctrl+C to stop                                                |
+======================================================================+
    """
    print(banner)

    init_db()

    # Start background scanner
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    # Start Flask
    try:
        app.run(host=APP_HOST, port=APP_PORT, debug=False)
    except KeyboardInterrupt:
        scanner_running = False
        print("\n[*] Shutting down...")
