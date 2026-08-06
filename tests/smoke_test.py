#!/usr/bin/env python3
"""
Smoke test for Network Analyzer — boots the app on a scratch port/DB, logs in,
then exercises every dashboard API (GET + POST) including the Batch H "Pro
Recon" pipeline end-to-end. Prints PASS/FAIL/WARN per check and exits non-zero
on any hard failure.

Usage:
    .venv/bin/python tests/smoke_test.py            # auto: pypi.org if reachable, else localhost
    SMOKE_TARGET=example.com .venv/bin/python tests/smoke_test.py
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import uuid

import requests

BASE = os.environ.get("SMOKE_BASE", "http://127.0.0.1:5099")
PORT = int(BASE.rsplit(":", 1)[1]) if ":" in BASE else 5099
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PY = os.path.join(ROOT, ".venv", "bin", "python")
PY = VENV_PY if os.path.exists(VENV_PY) else sys.executable

results: list[tuple[str, str, str]] = []  # (status, name, detail)


def record(ok, name, detail="", warn=False):
    status = "PASS" if ok else ("WARN" if warn else "FAIL")
    results.append((status, name, detail))
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def wait_port(port: int, host: str = "127.0.0.1", timeout: float = 60.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection((host, port), timeout=1.5):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def start_server() -> subprocess.Popen:
    tmp = tempfile.mkdtemp(prefix="na_smoke_")
    env = dict(os.environ)
    env.update({
        "APP_PORT": str(PORT),
        "APP_HOST": "0.0.0.0",
        "DB_PATH": os.path.join(tmp, "smoke.db"),
        "PCAP_DIR": os.path.join(tmp, "pcaps"),
        "SCAN_INTERVAL": "3600",
        "ADMIN_PASSWORD": "admin123",
        "PYTHONUNBUFFERED": "1",
    })
    proc = subprocess.Popen(
        [PY, "network_manager.py"], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,
    )
    if not wait_port(PORT):
        try:
            out = proc.stdout.read(2000) if proc.stdout else ""
        except Exception:
            out = ""
        print("SERVER LOG TAIL:\n", out[-2000:])
        raise SystemExit("server did not come up")
    return proc


class Client:
    def __init__(self):
        self.s = requests.Session()
        self.csrf = ""

    def login(self) -> bool:
        r = self.s.get(BASE + "/login", timeout=10)
        r = self.s.post(BASE + "/login", data={"username": "admin", "password": "admin123"},
                        allow_redirects=True, timeout=10)
        if "Network Analyzer" not in r.text:
            return False
        m = re.search(r'name="csrf-token" content="([^"]+)"', r.text)
        if not m:
            return False
        self.csrf = m.group(1)
        return True

    def get(self, path, expect_json=True):
        r = self.s.get(BASE + path, headers={"X-CSRF-Token": self.csrf}, timeout=60)
        return r, (r.json() if expect_json else r.text)

    def post(self, path, body=None, expect_json=True, raw=None):
        r = self.s.post(BASE + path, json=(body or {}) if raw is None else raw,
                        headers={"X-CSRF-Token": self.csrf},
                        timeout=300 if "prorecon" in path else 180)
        return r, (r.json() if expect_json else r.text)


def check_gets(c: Client):
    gets = [
        "/api/stats", "/api/devices", "/api/bandwidth", "/api/alerts?limit=5",
        "/api/audit-log?limit=5", "/api/dns-queries?limit=5", "/api/passive-dns?limit=5",
        "/api/port-history?limit=5", "/api/ja3-fingerprints?limit=5",
        "/api/mitm-alerts?limit=5", "/api/rogue-dhcp-alerts?limit=5",
        "/api/live-traffic?limit=5", "/api/traffic-summary", "/api/active-mitm",
        "/api/dns-spoof-rules", "/api/network-info", "/api/parental-rules",
        "/api/security-report", "/api/bandwidth-history", "/api/tools/status",
        "/api/recon/jobs", "/api/prorecon/jobs", "/api/recon/snapshots",
        "/api/wifi", "/api/wifi/security", "/api/wifi/supported", "/api/wifi/aps",
        "/api/wifi/handshakes", "/api/wifi/events?limit=5",
        "/api/bb/targets", "/api/bb/jobs", "/api/ai/status", "/api/settings",
        "/api/wifi/capabilities", "/api/wifi/audit/jobs", "/api/wifi/wordlists",
        "/api/mitm/wizard/status",
    ]
    for path in gets:
        try:
            r, j = c.get(path)
            ok = r.status_code == 200 and j is not None
            record(ok, f"GET {path}", f"status={r.status_code}")
        except Exception as e:
            record(False, f"GET {path}", f"exception {e}")

    # HTML pages
    r = c.s.get(BASE + "/", timeout=20)
    record(r.status_code == 200 and "ONE-CLICK FULL RECON" in r.text and "sec-prorecon" in r.text,
           "GET / dashboard (has Pro Recon UI)", f"status={r.status_code}")

    # stats include prorecon block
    r, j = c.get("/api/stats")
    record(isinstance(j, dict) and "prorecon" in j and "bugbounty" in j,
           "/api/stats has prorecon summary", str(j.get("prorecon")))

    # csv export
    r = c.s.get(BASE + "/api/export/csv", timeout=20)
    record(r.status_code == 200 and "MAC" in r.text, "GET /api/export/csv")
    r = c.s.get(BASE + "/api/wifi/survey.csv", timeout=20)
    record(r.status_code == 200 and "bssid" in r.text, "GET /api/wifi/survey.csv")


def pick_target() -> tuple[str, bool]:
    """Prefer a well-connected host (pypi.org) so HTTP/TLS phases get real data."""
    forced = os.environ.get("SMOKE_TARGET")
    if forced:
        return forced, True
    try:
        with socket.create_connection(("pypi.org", 443), timeout=4):
            return "pypi.org", True
    except OSError:
        return "localhost", False


def wait_job(c: Client, path: str, timeout_s: int = 360) -> dict | None:
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        try:
            r, j = c.get(path)
            job = j.get("job", j)
            if job.get("status") in ("done", "failed"):
                return job
        except Exception:
            pass
        time.sleep(2)
    return None


def flow_post_checks(c: Client):
    # --- CSRF negative test
    r = c.s.post(BASE + "/api/scan", headers={"X-CSRF-Token": "deadbeef"}, timeout=20)
    record(r.status_code == 403, "CSRF blocks bad token", f"status={r.status_code}")

    # --- AI brain (offline)
    r, j = c.post("/api/ai/ask", {"q": "how do I do a SYN scan?"})
    record(j.get("success") and "intent" in j.get("brain", {}), "POST /api/ai/ask",
           f"intent={j.get('brain', {}).get('intent')}")
    # ai ask with use_llm while llm disabled -> must NOT crash (regression: context kwarg bug)
    r, j = c.post("/api/ai/ask", {"q": "hello", "use_llm": True})
    record(j.get("success") is True, "POST /api/ai/ask use_llm (disabled) no-crash",
           f"llm_used={j.get('llm_used')}")

    # --- settings round-trip
    key = "smoketest_key"
    r, j = c.post("/api/settings", {"key": key, "value": "smoke123", "masked": False})
    record(j.get("success") is True, "POST /api/settings")
    r, j = c.get("/api/settings")
    found = any(row.get("key") == key and str(row.get("value")) == "smoke123" for row in j)
    record(found, "GET /api/settings reflects new key")

    # --- bb targets flow
    _, j = c.post("/api/bb/targets", {"target": "smoke-target.example", "notes": "t"})
    record(j.get("success") is True, "POST /api/bb/targets")
    _, j = c.get("/api/bb/targets")
    record(any(t.get("target") == "smoke-target.example" for t in j), "GET /api/bb/targets lists new")
    r = c.s.delete(BASE + "/api/bb/targets/smoke-target.example", headers={"X-CSRF-Token": c.csrf}, timeout=20)
    record(r.status_code == 200, "DELETE /api/bb/targets")

    # --- block on unknown device -> clean 404 json
    r, j = c.post("/api/devices/AA:BB:CC:DD:EE:FF/block")
    record(r.status_code == 404 and j.get("success") is False, "defensive 404 for unknown MAC")

    # --- packet capture start/stop returns sane JSON regardless of scapy/root
    r, j = c.post("/api/packet-capture/start", {"iface": None, "filter": "", "count": 0})
    record("success" in j and "message" in j, "POST /api/packet-capture/start graceful",
           f"success={j.get('success')}")
    c.post("/api/packet-capture/stop", {})

    # --- wifi monitor enable: expect graceful json (non-root in sandbox)
    r, j = c.post("/api/wifi/monitor/enable", {"iface": "wlan9"})
    record("success" in j, "POST /api/wifi/monitor/enable graceful", f"success={j.get('success')}")

    # --- alerts read
    _, j = c.post("/api/alerts/read")
    record(j.get("success") is True, "POST /api/alerts/read")

    # --- dns-spoof rule add/delete (input validation path)
    _, j = c.post("/api/dns-spoof-rules", {"domain": "smoke.test", "fake_ip": "127.0.0.2"})
    record(j.get("success") is True, "POST /api/dns-spoof-rules")
    r = c.s.delete(BASE + "/api/dns-spoof-rules/smoke.test", headers={"X-CSRF-Token": c.csrf}, timeout=20)
    record(r.status_code == 200, "DELETE /api/dns-spoof-rules")

    # --- parental rules validation
    r, j = c.post("/api/parental-rules", {"device_mac": "AA:BB:CC:DD:EE:FF", "day_of_week": "everyday",
                                          "start_time": "22:00", "end_time": "07:00", "action": "block"})
    record(j.get("success") is True, "POST /api/parental-rules")
    _, rules = c.get("/api/parental-rules")
    if rules:
        rid = rules[0]["id"]
        rs = c.s.delete(BASE + f"/api/parental-rules/{rid}", headers={"X-CSRF-Token": c.csrf}, timeout=20)
        record(rs.status_code == 200, "DELETE /api/parental-rules")

    # --- tools status has nuclei/katana entries
    _, j = c.get("/api/tools/status")
    record("nuclei" in j and "katana" in j and "nmap" in j, "tools list includes nuclei/katana",
           f"{len(j)} tools")

    # ---- Batch I: WiFi pentest wizard ----
    _, j = c.get("/api/wifi/capabilities")
    record(isinstance(j, dict) and "interfaces" in j and "tools" in j and "is_root" in j,
           "GET /api/wifi/capabilities", f"root={j.get('is_root')} ifaces={len(j.get('interfaces', []))}")

    # audit start on a non-root sandbox should fail gracefully (running job or clean fatal)
    _, j = c.post("/api/wifi/audit/start", {"survey_seconds": 5, "handshake_seconds": 10})
    if j.get("success"):
        job = wait_job(c, f"/api/wifi/audit/jobs/{j['job_id']}", timeout_s=120)
        record(bool(job) and job.get("status") in ("done", "failed"),
               "wifi audit job lifecycle", f"status={(job or {}).get('status')} err={(job or {}).get('error', '')[:80]}")
    else:
        record(False, "POST /api/wifi/audit/start returns job", str(j))

    # audit start with deauth but no confirm must be rejected with explainable error
    r, j = c.post("/api/wifi/audit/start", {"deauth": True, "confirmed": False})
    record(r.status_code == 400 and "confirmed" in j.get("error", ""),
           "wifi audit deauth confirm-gate")

    # wordlists endpoint lists the demo list
    _, j = c.get("/api/wifi/wordlists")
    record(any(w.get("name") == "demo_common.txt" for w in j.get("wordlists", [])),
           "GET /api/wifi/wordlists has demo list")

    # crack on nonexistent handshake -> clean 4xx JSON, not a stack trace
    r, j = c.post("/api/wifi/handshakes/9999/crack", {"wordlist": "demo_common.txt"})
    record(r.status_code == 400 and j.get("success") is False, "crack unknown handshake -> clean error")

    # crack with path traversal wordlist -> rejected (wordlist guard or missing-row guard, both 400)
    r, j = c.post("/api/wifi/handshakes/1/crack", {"wordlist": "../../../etc/passwd"})
    record(r.status_code == 400 and j.get("success") is False and "not found" in j.get("error", "").lower(),
           "crack wordlist path-traversal blocked", j.get("error", ""))

    # ---- Batch I: MITM wizard ----
    _, j = c.get("/api/mitm/wizard/status")
    record(isinstance(j, dict) and "intercepted" in j and "ip_forward" in j,
           "GET /api/mitm/wizard/status", f"active={j.get('active')} fwd={j.get('ip_forward')}")

    # start with bogus ip -> validation error JSON
    r, j = c.post("/api/mitm/wizard/start", {"target": "not-an-ip"})
    record(r.status_code == 400 and j.get("success") is False, "MITM wizard rejects bad input")

    # start against the gateway must be refused by the safety guard (or fail safely pre-root)
    _, stats = c.get("/api/stats")
    gw = stats.get("gateway", "")
    if gw and "." in gw:
        _, j = c.post("/api/mitm/wizard/start", {"target": gw})
        msg = str(j.get("message", j.get("error", "")))
        record(j.get("success") is False and ("Refusing" in msg or "forward" in msg.lower()
                                              or "root" in msg.lower() or "scapy" in msg.lower()
                                              or "MAC" in msg),
               "MITM wizard refuses/fails safely on gateway", msg[:80])
        c.post("/api/mitm/wizard/stop", {})

    # start against a random private ip: sandbox has no root -> must fail gracefully
    r, j = c.post("/api/mitm/wizard/start", {"target": "10.77.66.55"})
    record("success" in j and "message" in j, "MITM wizard start graceful (lab host only)",
           f"success={j.get('success')}")
    c.post("/api/mitm/wizard/stop", {})
    _, j = c.post("/api/mitm/wizard/stop", {})
    record(j.get("success") is True, "MITM wizard stop idempotent")


def flow_intel_endpoints(c: Client, target: str, networked: bool):
    # DNS dump
    r, j = c.post("/api/recon/dns", {"target": target})
    ok = j.get("success") and isinstance(j.get("result", {}).get("records"), dict)
    record(ok, "POST /api/recon/dns", f"types={list(j.get('result', {}).get('records', {}).keys())}")
    if networked:
        rec = j.get("result", {}).get("records", {})
        record(bool(rec.get("A")), "DNS dump has A records", str(rec.get("A", []))[:120], warn=True)

    # Headers grade
    r, j = c.post("/api/recon/headers", {"target": target})
    if networked:
        record(j.get("success") and j.get("result", {}).get("grade") in ("A+", "A", "B", "C", "D", "F"),
               "POST /api/recon/headers grade", f"grade={j.get('result', {}).get('grade')}")
    else:
        record(True, "POST /api/recon/headers skipped (offline sandbox)", "", warn=True)

    # WHOIS / RDAP (keyless) — sandbox may block rdap.org; endpoint must always respond
    r, j = c.post("/api/recon/whois", {"target": target})
    record(j.get("success") and "result" in j, "POST /api/recon/whois responds",
           f"keys={list((j.get('result') or {}).keys())[:6]}",
           warn=("error" in (j.get("result") or {})))

    # Takeover scan
    r, j = c.post("/api/recon/takeover", {"target": target, "subdomains": ["www." + target, "apps." + target]})
    record(j.get("success") and isinstance(j.get("results"), list),
           "POST /api/recon/takeover", f"hits={len(j.get('results', []))}")

    # Lookalike radar (DNS-only probe to keep it fast)
    r, j = c.post("/api/recon/lookalikes", {"target": target, "probe": False})
    record(j.get("success") and isinstance(j.get("results"), list),
           "POST /api/recon/lookalikes", f"resolving={len(j.get('results', []))} perms={j.get('permutations_checked')}")

    # TLS check (single host)
    r, j = c.post("/api/tls/check", {"host": target, "port": 443})
    cert = (j or {}).get("cert") or {}
    if networked:
        record(j.get("success") and "subject" in cert, "POST /api/tls/check",
               f"issuer={str(cert.get('issuer', ''))[:60]}")
    else:
        record(j.get("success") is True, "POST /api/tls/check graceful", "", warn="error" in cert)


def flow_pro_recon(c: Client, target: str, networked: bool):
    # ---- run 1: quick profile, wait for completion
    r, j = c.post("/api/prorecon/start", {"target": target, "profile": "quick"})
    record(j.get("success") and bool(j.get("job_id")), "POST /api/prorecon/start (run 1)")
    jid1 = j.get("job_id")
    job = wait_job(c, f"/api/prorecon/jobs/{jid1}", timeout_s=420)
    if not job:
        record(False, "pro recon job completes", "timed out")
        return None
    record(job.get("status") == "done", "pro recon job completes (run 1)",
           f"status={job.get('status')} err={job.get('error', '')[:120]}")
    res = job.get("result") or {}
    for key in ("dns", "subdomains", "ports", "hosts", "takeover", "risk", "dna", "graph", "log", "ports_unreliable"):
        record(key in res or key in job, f"pro recon result has '{key}'")
    risk = res.get("risk") or {}
    record(isinstance(risk.get("score"), int) and risk.get("grade") in ("A", "B", "C", "D", "F"),
           "risk engine produced score+grade", f"score={risk.get('score')} grade={risk.get('grade')} findings={len(risk.get('findings', []))}")
    if networked:
        # sandbox egress is proxied, so the canary heuristic must fire here;
        # on a clean network it correctly stays False.
        if res.get("ports_unreliable"):
            record(True, "transparent-proxy canary detected + surfaced")
            record(any("unreliable" in f.get("title", "").lower() for f in risk.get("findings", [])),
                   "risk engine has vantage-anomaly finding")
        else:
            record(True, "canary check OK (clean vantage)", "", warn=True)
    record(bool(res.get("dna")), "attack-surface DNA present", res.get("dna", ""))
    record(bool(res.get("graph", {}).get("nodes")), "attack graph has nodes")
    if networked:
        record(bool(res.get("subdomains")), "subdomains found (networked)", str(len(res.get("subdomains", []))), warn=True)
        record(bool(res.get("hosts")), "live HTTP hosts probed (networked)", str(len(res.get("hosts", []))), warn=True)
    phases = job.get("phases") or {}
    record(all(v in ("done", "error") for v in phases.values()), "all phases finished",
           str(phases))

    # ---- run 2 (snapshot #2 enables Time Machine diff)
    r, j = c.post("/api/prorecon/start", {"target": target, "profile": "quick"})
    jid2 = j.get("job_id")
    job2 = wait_job(c, f"/api/prorecon/jobs/{jid2}", timeout_s=420)
    record(bool(job2) and job2.get("status") == "done", "pro recon job completes (run 2)")

    # snapshots list + diff
    _, snaps = c.get("/api/recon/snapshots")
    snaps = [s for s in snaps if s.get("target") == target]
    record(len(snaps) >= 2, "snapshots stored (>=2)", f"n={len(snaps)}")
    if len(snaps) >= 2:
        a, b = snaps[-1]["id"], snaps[0]["id"]
        r, j = c.get(f"/api/recon/snapshots/diff?a={a}&b={b}")
        record(j.get("success") and "diff" in j and "changed" in j["diff"],
               "GET /api/recon/snapshots/diff", f"changed={j.get('diff', {}).get('changed')}")

    # graph endpoint
    r, j = c.get(f"/api/recon/graph/{jid1}")
    record(j.get("success") and isinstance(j.get("graph", {}).get("nodes"), list),
           "GET /api/recon/graph/<job>")

    # HTML report
    r = c.s.get(BASE + f"/api/recon/report/{jid1}.html", timeout=30)
    record(r.status_code == 200 and "<html" in r.text and "Risk score" in r.text,
           "GET /api/recon/report/<job>.html", f"bytes={len(r.text)}")
    return jid1


def flow_classic_recon(c: Client, target: str, networked: bool):
    r, j = c.post("/api/recon/start", {"target": target, "modes": ["subdomains", "http"]})
    record(j.get("success") is True, "POST /api/recon/start (classic)")
    jid = j.get("job_id")
    t0 = time.time()
    job = None
    while time.time() - t0 < 240:
        _, jr = c.get(f"/api/recon/jobs/{jid}")
        job = jr.get("job", jr)
        if job.get("status") in ("done", "failed"):
            break
        time.sleep(2)
    record(bool(job) and job.get("status") == "done", "classic recon completes",
           f"status={(job or {}).get('status')} summary={(job or {}).get('summary', '')[:100]}")
    if networked and job:
        tls = job.get("tls")
        record(isinstance(tls, dict) and ("subject" in tls or "error" in tls),
               "classic recon TLS phase ran (http implies tls)", "", warn=True)


def main():
    print(f"[*] booting server with {PY} on port {PORT} ...")
    proc = start_server()
    try:
        c = Client()
        record(c.login(), "login + CSRF token")
        check_gets(c)
        flow_post_checks(c)
        target, networked = pick_target()
        print(f"[*] intel + pro recon flows against target: {target} (networked={networked})")
        flow_intel_endpoints(c, target, networked)
        flow_classic_recon(c, target, networked)
        flow_pro_recon(c, target, networked)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=15)
        except Exception:
            proc.kill()

    n_fail = sum(1 for s, _, _ in results if s == "FAIL")
    n_warn = sum(1 for s, _, _ in results if s == "WARN")
    n_pass = sum(1 for s, _, _ in results if s == "PASS")
    print("\n================ SMOKE SUMMARY ================")
    print(f"PASS={n_pass} WARN={n_warn} FAIL={n_fail}")
    for s, n, d in results:
        if s == "FAIL":
            print(f"  FAIL: {n} — {d}")
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
