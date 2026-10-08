"""
Attack #8: Vulnerability Scan
=====================================
SCADANet stats: 40,870 packets, frame_delta≈0.0s, Http_content=5374B -> ~68 pkt/s
Scans for ICS-specific vulnerabilities: default passwords, exposed Modbus, insecure HTTP.
Effect: builds a weak-point map -> enables preparation of a target-specific exploit.

MITRE ATT&CK for ICS: T0887 - Wireless Sniffing / T0855 - Unauthorized Command Message
Zeek signature: http.log + conn.log -> many distinct endpoints, user-agent
"""

import time
import sys
import os
import socket
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    PLC_IP, HMI_IP, HMI_PORT, MODBUS_PORT,
    DEFAULT_NET_DURATION, LABEL_VULN_SCAN, NET_DURATIONS
)

ATTACK_NAME = "Vulnerability_Scan"
ATTACK_ID   = LABEL_VULN_SCAN

SCAN_INTERVAL = 1.0 / 68.0   # ~68 pkt/s

# ICS-specific vulnerability checks
VULN_CHECKS = [
    # (type, target_port, endpoint/payload, description)
    ("http", HMI_PORT, "/",                          "HMI home page access"),
    ("http", HMI_PORT, "/api/flows",                 "Node-RED flow listing"),
    ("http", HMI_PORT, "/api/nodes",                 "Node-RED node listing"),
    ("http", HMI_PORT, "/credentials",               "Credentials endpoint"),
    ("http", HMI_PORT, "/settings",                  "Settings endpoint"),
    ("http", HMI_PORT, "/.env",                      ".env file leak"),
    ("http", HMI_PORT, "/admin",                     "Admin panel attempt"),
    ("http", HMI_PORT, "/api/admin/auth",            "Auth bypass attempt"),
    ("http", 8086, "/query?q=SHOW+DATABASES",        "InfluxDB query"),
    ("http", 8086, "/query?q=SHOW+MEASUREMENTS",     "InfluxDB measurement listing"),
    ("http", 3000, "/api/dashboards/home",           "Grafana dashboard"),
    ("modbus", MODBUS_PORT, "read_device_info",      "Modbus FC43 device info"),
    ("modbus", MODBUS_PORT, "read_all_coils",        "Modbus FC1 read all coils"),
    ("modbus", MODBUS_PORT, "read_all_registers",    "Modbus FC3 read all registers"),
    ("tcp",    22, None,                             "SSH version banner"),
    ("tcp",    23, None,                             "Is Telnet open?"),
    ("tcp",    MODBUS_PORT, None,                    "Is Modbus open?"),
]

# SCADANet Http_content_length=5374B -> mimics realistic user-agent string length
FAKE_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Nessus/10.0; +https://www.tenable.com)",
    "Mozilla/5.0 (compatible; OpenVAS/21.4)",
    "Nikto/2.1.6 (Evasions:None)",
    "python-requests/2.28.0",
    "curl/7.88.1",
]


def _http_check(ip: str, port: int, path: str) -> dict:
    """Send an HTTP GET request and capture the response code."""
    ua = random.choice(FAKE_USER_AGENTS)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {ip}:{port}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        s.sendall(req)
        resp = s.recv(512).decode(errors="replace")
        s.close()
        code = resp.split(" ")[1] if " " in resp else "???"
        return {"status": code, "response": resp[:80]}
    except Exception as e:
        return {"status": "ERR", "response": str(e)[:40]}


def _modbus_check(ip: str, port: int, check_type: str) -> dict:
    """Simple Modbus connection and read attempt."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        # Modbus FC3 Read Holding Registers (0-9)
        mbap  = b'\x00\x01\x00\x00\x00\x06\x01'
        pdu   = b'\x03\x00\x00\x00\x0a'   # FC3, addr=0, count=10
        s.sendall(mbap + pdu)
        resp = s.recv(128)
        s.close()
        return {"status": "OPEN", "response": f"{len(resp)} bytes received"}
    except Exception as e:
        return {"status": "ERR", "response": str(e)[:40]}


def _tcp_banner(ip: str, port: int) -> dict:
    """TCP banner grabbing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        banner = s.recv(256).decode(errors="replace").strip()[:60]
        s.close()
        return {"status": "OPEN", "banner": banner}
    except Exception as e:
        return {"status": "ERR", "response": str(e)[:40]}


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("vuln_scan", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {target_ip} (HMI:{HMI_PORT}, Modbus:{MODBUS_PORT})")
    print(f"  {len(VULN_CHECKS)} ICS vulnerability checks")
    print(f"  Rate: ~68 pkt/s | Duration: {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"Vuln scan -> {target_ip}, {len(VULN_CHECKS)} checks, ~68pkt/s"
        )

    start_time = time.time()
    pkt_count  = 0
    findings   = []

    try:
        while (time.time() - start_time) < duration_sec:
            for check_type, port, endpoint, desc in VULN_CHECKS:
                if (time.time() - start_time) >= duration_sec:
                    break

                if check_type == "http":
                    result = _http_check(target_ip, port, endpoint)
                    code   = result["status"]
                    flag   = "[+]" if code in ("200", "401") else "[ ]"
                    if code in ("200", "401", "301", "302"):
                        findings.append((desc, code, endpoint))
                    if pkt_count % 50 == 0:
                        print(f"  [VULN] {flag} HTTP:{port}{endpoint} -> {code}")

                elif check_type == "modbus":
                    result = _modbus_check(target_ip, port, endpoint)
                    if result["status"] == "OPEN":
                        findings.append((desc, "EXPOSED", "Modbus"))
                        print(f"  [VULN] {desc} -> {result['response']}")

                elif check_type == "tcp":
                    result = _tcp_banner(target_ip, port)
                    if result["status"] == "OPEN":
                        findings.append((desc, "OPEN", f":{port}"))

                pkt_count += 1
                time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print("\n  [VULN] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        print(f"\n  [VULN] {len(findings)} vulnerabilities found:")
        for f in findings:
            print(f"         -> {f[0]} [{f[1]}]")

        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} checks, {len(findings)} findings, {elapsed:.1f}s"
            )
        print(f"\n  [VULN] {pkt_count} checks | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
