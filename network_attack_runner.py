#!/usr/bin/env python3
"""
SCADA-CPS Testbed - Network-Layer Attack Orchestrator
========================================================
Runs the attacks under network_attacks/ either as a full sequence or
individually selected by ID.
"""

import sys
import os
import time
import argparse
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attacks.label_manager import LabelManager
from network_attacks.net_config import (
    PLC_IP, NETWORK_ATTACK_NAMES, NET_DURATIONS, DEFAULT_NET_DURATION
)

# Network attack modules
from network_attacks.attack_net_01_icmp_flood import run_attack as net_01
from network_attacks.attack_net_02_udp_flood import run_attack as net_02
from network_attacks.attack_net_03_tcp_syn_flood import run_attack as net_03
from network_attacks.attack_net_04_tcp_ack_flood import run_attack as net_04
from network_attacks.attack_net_05_http_flood import run_attack as net_05
from network_attacks.attack_net_06_port_scan import run_attack as net_06
from network_attacks.attack_net_07_os_scan import run_attack as net_07
from network_attacks.attack_net_08_vuln_scan import run_attack as net_08
from network_attacks.attack_net_09_nodered_injection import run_attack as net_09
from network_attacks.attack_net_10_insider_threat import run_attack as net_10
from network_attacks.attack_net_11_apt_exfil import run_attack as net_11
from network_attacks.attack_net_12_modbus_abuse import run_attack as net_12

NET_ATTACK_SEQUENCE = [
    (101, net_01, "icmp_flood", NETWORK_ATTACK_NAMES[101]),
    (102, net_02, "udp_flood", NETWORK_ATTACK_NAMES[102]),
    (103, net_03, "tcp_syn_flood", NETWORK_ATTACK_NAMES[103]),
    (104, net_04, "tcp_ack_flood", NETWORK_ATTACK_NAMES[104]),
    (105, net_05, "http_flood", NETWORK_ATTACK_NAMES[105]),
    (106, net_06, "port_scan", NETWORK_ATTACK_NAMES[106]),
    (107, net_07, "os_scan", NETWORK_ATTACK_NAMES[107]),
    (108, net_08, "vuln_scan", NETWORK_ATTACK_NAMES[108]),
    (109, net_09, "nodered_injection", NETWORK_ATTACK_NAMES[109]),
    (110, net_10, "insider_threat", NETWORK_ATTACK_NAMES[110]),
    (111, net_11, "apt_exfil", NETWORK_ATTACK_NAMES[111]),
    (112, net_12, "modbus_abuse", NETWORK_ATTACK_NAMES[112]),
]

def print_banner():
    print()
    print("+" + "-"*63 + "+")
    print("|" + " SCADA-CPS TESTBED - NETWORK ATTACK ORCHESTRATOR".center(63) + "|")
    print("+" + "-"*63 + "+")
    print("|" + f" Target: {PLC_IP}".ljust(63) + "|")
    print("|" + f" Date  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".ljust(63) + "|")
    print("+" + "-"*63 + "+")
    print()

def wait_period(seconds, period_name="Waiting"):
    print(f"\n  {period_name}: {seconds} seconds")
    start = time.time()
    while (time.time() - start) < seconds:
        time.sleep(1)

def run_orchestrator(attack_time=None, selected_attacks=None, break_time=60):
    print_banner()

    if selected_attacks:
        attacks = [(aid, fn, key, nm) for aid, fn, key, nm in NET_ATTACK_SEQUENCE
                   if (aid - 100) in selected_attacks]
    else:
        attacks = NET_ATTACK_SEQUENCE

    total_attacks = len(attacks)
    print(f"  Network attacks to run: {total_attacks}")
    print()

    dataset_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
    if not os.path.exists(dataset_dir):
        os.makedirs(dataset_dir)

    lm = LabelManager(output_dir=dataset_dir, plc_ip=PLC_IP)

    for idx, (attack_id, attack_fn, duration_key, attack_name) in enumerate(attacks, 1):
        if attack_time is not None:
            duration = attack_time
        else:
            duration = NET_DURATIONS.get(duration_key, DEFAULT_NET_DURATION)

        print("=" * 65)
        print(f"  [{idx}/{total_attacks}] NETWORK ATTACK: {attack_name}")
        print(f"  Duration: {duration}s | Start: {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 65)

        try:
            attack_fn(duration_sec=duration, label_manager=lm)
        except Exception as e:
            print(f"\n  [ERROR] Attack failed: {e}")
            lm.log_attack_end(attack_id, attack_name, f"ERROR: {e}")

        if idx < total_attacks:
            wait_period(break_time, "REST")

    print(f"\n  NETWORK ATTACKS COMPLETE")
    print(f"  Label file: {lm.get_labels_path()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SCADA-CPS Testbed - Network Attack Orchestrator")
    parser.add_argument("--attacks", type=str, default=None, help="Attack IDs to run (1-12, comma-separated). Example: 1,3,5")
    parser.add_argument("--attack-time", type=int, default=None, help="Fixed duration (s) applied to every network attack")
    parser.add_argument("--break-time", type=int, default=60, help="Rest period between attacks (s). Default: 60")
    args = parser.parse_args()

    selected = None
    if args.attacks:
        selected = [int(x.strip()) for x in args.attacks.split(",")]

    try:
        run_orchestrator(attack_time=args.attack_time, selected_attacks=selected, break_time=args.break_time)
    except KeyboardInterrupt:
        print("\n\n  [!] Orchestrator stopped by user!")
        sys.exit(1)
