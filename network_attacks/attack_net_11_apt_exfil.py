"""
Attack #11: APT Exfiltration (Advanced Persistent Threat - Data Leak)
==============================================================================
SCADANet stats: 2,425 packets, Tcp_len≈68B, frame_delta≈0.0s -> ~4 pkt/s
Very slow, covert data exfiltration. Avoids triggering IDS.
Effect: long-term unauthorized information gathering, leakage of operational secrets.

MITRE ATT&CK for ICS: T0882 - Theft of Operational Information
Zeek signature: conn.log -> long connection duration, small but regular transfers
"""

import time
import sys
import os
import socket
import random
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    PLC_IP, HMI_IP, HMI_PORT, MODBUS_PORT,
    DEFAULT_NET_DURATION, LABEL_APT_EXFIL, NET_DURATIONS
)

ATTACK_NAME = "APT_Exfiltration"
ATTACK_ID   = LABEL_APT_EXFIL

# SCADANet: ~4 pkt/s, Tcp_len=68B -> small, regular transfer
PKT_INTERVAL = 0.25    # seconds (4 pkt/s)
EXFIL_CHUNK  = 68      # SCADANet Tcp_len mean (68 bytes per packet)

# Data collection targets (collect first, then simulate exfiltration)
COLLECTION_TARGETS = [
    ("modbus", MODBUS_PORT, "register_dump"),
    ("http",   HMI_PORT,    "/api/flows"),
    ("http",   HMI_PORT,    "/settings"),
    ("http",   8086,        "/query?q=SELECT+*+FROM+scada_testbed"),
]

# Fake C2 (Command & Control) server info (NO real connection is made)
# This is for simulation only. No connection is actually made to this IP.
# Outbound connections in Zeek will appear to be toward this IP.
C2_IP   = "10.10.10.10"    # IP that does not exist on the isolated lab network
C2_PORT = 4444


def _collect_modbus_data(ip: str, port: int) -> bytes:
    """Collect data from Modbus."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((ip, port))
        req = b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x1c'
        s.sendall(req)
        data = s.recv(128)
        s.close()
        return data
    except Exception:
        return b'\x00' * 56


def _collect_hmi_data(ip: str, port: int, path: str) -> bytes:
    """Collect data from the HMI."""
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {ip}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((ip, port))
        s.sendall(req)
        data = s.recv(2048)
        s.close()
        return data[:EXFIL_CHUNK * 10]
    except Exception:
        return b''


def _simulate_exfil(collected_data: bytes, chunk_size: int) -> int:
    """
    Data exfiltration simulation.
    Does not actually connect to a C2; only loops for CPU/network metrics.
    This connection is visible in Zeek (if C2_IP is reachable).
    """
    chunks_sent = 0
    encoded     = base64.b64encode(collected_data)   # Mimics obfuscation

    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i+chunk_size]
        # Instead of a real C2 connection: simulation (just spend time)
        time.sleep(PKT_INTERVAL * 0.5)
        chunks_sent += 1

    return chunks_sent


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("apt_exfil", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {target_ip} (Modbus + HMI + InfluxDB)")
    print(f"  Scenario: APT -> covert data collection + simulated C2 exfiltration")
    print(f"  Chunk: {EXFIL_CHUNK}B/packet | Rate: ~4 pkt/s")
    print(f"  Duration: {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"APT exfil -> {target_ip}, {EXFIL_CHUNK}B chunk, ~4pkt/s"
        )

    start_time    = time.time()
    cycle         = 0
    total_chunks  = 0
    total_bytes   = 0

    try:
        while (time.time() - start_time) < duration_sec:
            cycle += 1

            # Phase 1: data collection (slowly, from the inside)
            collected = b''
            for src_type, port, path in COLLECTION_TARGETS:
                if (time.time() - start_time) >= duration_sec:
                    break
                if src_type == "modbus":
                    data = _collect_modbus_data(target_ip, port)
                else:
                    data = _collect_hmi_data(target_ip, port, path)
                collected   += data
                total_bytes += len(data)
                time.sleep(PKT_INTERVAL)

            # Phase 2: exfiltration simulation
            chunks = _simulate_exfil(collected, EXFIL_CHUNK)
            total_chunks += chunks

            if cycle % 3 == 0:
                elapsed = time.time() - start_time
                rem     = duration_sec - elapsed
                print(f"  [APT]  Cycle {cycle} | "
                      f"{total_bytes/1024:.1f}KB collected | "
                      f"{total_chunks} chunks exfiltrated | remaining: {rem:.0f}s")

            time.sleep(PKT_INTERVAL * 2)

    except KeyboardInterrupt:
        print("\n  [APT] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{cycle} cycles, {total_bytes/1024:.1f}KB collected, "
                f"{total_chunks} chunks, {elapsed:.1f}s"
            )
        print(f"\n  [APT] {total_bytes/1024:.1f}KB | {total_chunks} chunks | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
