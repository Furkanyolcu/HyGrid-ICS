"""
Attack #6: Port Scan (Remote System Discovery)
==================================================================
Reference rate from SCADANet calibration: 1,561 packets, frame_delta ~ 0.47s -> ~5 pkt/s (slow scan).
Discovers open ports on the target system. Highly dangerous for ICS environments.
Effect: the attacker learns which Modbus/HMI ports are open and plans a targeted attack.

MITRE ATT&CK for ICS: T0846 - Remote System Discovery
Zeek signature: conn.log -> state=S0/REJ, uid, id.resp_p (port), service
"""

import time
import sys
import os
import socket

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    PLC_IP, DEFAULT_NET_DURATION,
    LABEL_PORT_SCAN, NET_DURATIONS
)

ATTACK_NAME = "Port_Scan"
ATTACK_ID   = LABEL_PORT_SCAN

# SCADANet frame_delta=0.47s -> slow, stealthy scan
SCAN_INTERVAL = 0.47   # Seconds per port (per SCADANet calibration)

# Critical ports for ICS/SCADA plus common general services
ICS_PORTS = [
    # ICS protocols
    502, 102, 4840, 1911, 2404, 44818, 9600, 19999, 20000, 34962,
    # General services
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443,
    # Node-RED / InfluxDB / Grafana
    1880, 8086, 3000, 1883, 8883,
    # Database
    3306, 5432, 27017, 6379,
]


def _tcp_connect_scan(ip: str, port: int, timeout: float = 0.3) -> str:
    """TCP connect scan. Fast, does not require root."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return "OPEN"
            elif result in (111, 10061):   # Connection refused
                return "CLOSED"
            else:
                return "FILTERED"
    except socket.timeout:
        return "FILTERED"
    except Exception:
        return "ERROR"


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("port_scan", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    open_ports   = []
    closed_ports = []
    filtered_ports = []

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target  : {target_ip}")
    print(f"  Scanning: {len(ICS_PORTS)} ICS/general ports")
    print(f"  Interval: {SCAN_INTERVAL}s/port (stealthy scan)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"Port scan -> {target_ip}, {len(ICS_PORTS)} ports, {SCAN_INTERVAL}s interval"
        )

    start_time = time.time()
    scanned    = 0

    try:
        while (time.time() - start_time) < duration_sec:
            # Repeat the scan until the duration elapses
            for port in ICS_PORTS:
                if (time.time() - start_time) >= duration_sec:
                    break

                status = _tcp_connect_scan(target_ip, port)
                scanned += 1

                if status == "OPEN":
                    open_ports.append(port)
                    print(f"  [SCAN] PORT {port:5d}/tcp  ->  OPEN  <<<")
                elif status == "CLOSED":
                    closed_ports.append(port)
                elif status == "FILTERED":
                    filtered_ports.append(port)

                time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print("\n  [SCAN] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        print(f"\n  [SCAN] Scan results:")
        print(f"         Open ports : {open_ports}")
        print(f"         Scanned    : {scanned} ports | {elapsed:.1f}s")

        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{scanned} ports scanned, {len(open_ports)} open: {open_ports}, {elapsed:.1f}s"
            )
    return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
