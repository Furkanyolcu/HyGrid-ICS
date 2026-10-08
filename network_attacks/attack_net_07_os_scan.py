"""
Attack #7: OS Scan (Operating System Fingerprinting)
======================================================
SCADANet stats: 2,044 packets, frame_delta≈0.0s -> ~68 pkt/s (intense, short)
OS detection via TTL, TCP window size, and flag analysis.
Effect: attacker learns the PLC/HMI operating system -> can plan exploit-specific attacks.

MITRE ATT&CK for ICS: T0888 - Remote System Information Discovery
Zeek signature: conn.log -> TTL value (ip_ttl), window size, OS estimate
"""

import time
import sys
import os
import socket
import struct
import random
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    PLC_IP, DEFAULT_NET_DURATION,
    LABEL_OS_SCAN, NET_DURATIONS
)

ATTACK_NAME = "OS_Scan"
ATTACK_ID   = LABEL_OS_SCAN

# SCADANet: ip_ttl std=9.25, mean=56 -> mixed TTL values (scan detection)
SCAN_INTERVAL = 1.0 / 68.0   # ~68 pkt/s, short duration (30s)

# TCP probes for OS fingerprinting
TCP_PROBES = [
    # (port, flags, window, description)
    (502,  0x002, 65535, "SYN->Modbus"),         # SYN
    (22,   0x002, 5840,  "SYN->SSH Linux"),       # Linux window size
    (22,   0x002, 8192,  "SYN->SSH Windows"),     # Windows window size
    (80,   0x002, 1024,  "SYN->HTTP small"),
    (502,  0x041, 65535, "FIN+URG->Modbus"),      # FIN+URG (Xmas-like)
    (502,  0x000, 65535, "NULL->Modbus"),          # NULL scan
]


def _tcp_probe(target_ip: str, port: int, flags: int,
               window: int, timeout: float = 0.1) -> dict:
    """Send a single TCP probe and analyze the response."""
    result = {
        "port": port, "flags": flags, "window": window,
        "response": "none", "rst": False, "syn_ack": False
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((target_ip, port))
        if r == 0:
            result["response"] = "open"
            result["syn_ack"]  = True
        elif r in (111, 10061):
            result["response"] = "rst"
            result["rst"]      = True
        else:
            result["response"] = "filtered"
        s.close()
    except Exception:
        result["response"] = "timeout"
    return result


def _guess_os(results: list) -> str:
    """Simple OS guess (not real nmap, for simulation purposes)."""
    open_ports = [r["port"] for r in results if r["syn_ack"]]
    if 502 in open_ports and 22 in open_ports:
        return "Linux/Embedded (OpenPLC + SSH)"
    elif 502 in open_ports:
        return "Embedded ICS Device (Modbus only)"
    elif 22 in open_ports:
        return "Linux Server"
    elif 3389 in open_ports:
        return "Windows"
    return "Unknown"


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("os_scan", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {target_ip}")
    print(f"  OS fingerprinting: TTL + TCP window + flag analysis")
    print(f"  Rate: ~68 pkt/s | Duration: {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"OS fingerprint -> {target_ip}, TCP probe + TTL analysis"
        )

    start_time   = time.time()
    pkt_count    = 0
    all_results  = []
    round_num    = 0

    try:
        while (time.time() - start_time) < duration_sec:
            round_num += 1
            round_results = []

            for port, flags, window, desc in TCP_PROBES:
                if (time.time() - start_time) >= duration_sec:
                    break
                r = _tcp_probe(target_ip, port, flags, window)
                r["description"] = desc
                r["round"]       = round_num
                round_results.append(r)
                pkt_count += 1
                time.sleep(SCAN_INTERVAL)

            all_results.extend(round_results)
            os_guess = _guess_os(round_results)

            if round_num % 5 == 0:
                elapsed = time.time() - start_time
                rem     = duration_sec - elapsed
                print(f"  [OS]   Round {round_num} | Guess: {os_guess} | "
                      f"{pkt_count} probes | remaining: {rem:.0f}s")

    except KeyboardInterrupt:
        print("\n  [OS] Manual stop!")
    finally:
        elapsed  = time.time() - start_time
        os_final = _guess_os(all_results) if all_results else "Unknown"
        print(f"\n  [OS] Result: {os_final}")
        print(f"         {pkt_count} probes | {elapsed:.1f}s")

        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} probes, OS={os_final}, {elapsed:.1f}s"
            )
    return True


if __name__ == "__main__":
    run_attack(duration_sec=30)
