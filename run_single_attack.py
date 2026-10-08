#!/usr/bin/env python3
"""
SCADA-CPS Testbed - Single Attack Launcher
=============================================
Launches any one physical attack individually. Ground-truth labeling is
handled automatically (labels_single.csv).

Usage:
  python run_single_attack.py                        # interactive menu
  python run_single_attack.py --id 1                 # attack #1 (default duration)
  python run_single_attack.py --id 3 --duration 120  # attack #3, 2 minutes
  python run_single_attack.py --id 5 --no-label      # attack #5, no labeling
  python run_single_attack.py --list                 # list all attacks
"""

import sys
import os
import argparse
from datetime import datetime

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attacks.label_manager import LabelManager
from attacks.config import (
    PLC_IP, PLC_PORT, ATTACK_DURATIONS,
    DEFAULT_ATTACK_DURATION, ATTACK_NAMES
)

# --- 17 attack modules ---
from attacks.attack_01_fdi_voltage import run_attack as attack_01
from attacks.attack_02_coil_manipulation import run_attack as attack_02
from attacks.attack_03_diag_flood import run_attack as attack_03
from attacks.attack_04_illegal_address import run_attack as attack_04
from attacks.attack_05_fc_fuzzing import run_attack as attack_05
from attacks.attack_06_load_sabotage import run_attack as attack_06
from attacks.attack_07_gen_overload import run_attack as attack_07
from attacks.attack_08_voltage_instability import run_attack as attack_08
from attacks.attack_09_battery_drain import run_attack as attack_09
from attacks.attack_10_thermal_sabotage import run_attack as attack_10
from attacks.attack_11_freq_desync import run_attack as attack_11
from attacks.attack_12_reactive_power import run_attack as attack_12
from attacks.attack_13_bus_overload import run_attack as attack_13
from attacks.attack_14_ramp_attack import run_attack as attack_14
from attacks.attack_15_impossible_state import run_attack as attack_15
from attacks.attack_16_false_alarm import run_attack as attack_16
from attacks.attack_17_modbus_recon import run_attack as attack_17

# --- attack-ID -> function map ---
ATTACK_MAP = {
    1:  attack_01,
    2:  attack_02,
    3:  attack_03,
    4:  attack_04,
    5:  attack_05,
    6:  attack_06,
    7:  attack_07,
    8:  attack_08,
    9:  attack_09,
    10: attack_10,
    11: attack_11,
    12: attack_12,
    13: attack_13,
    14: attack_14,
    15: attack_15,
    16: attack_16,
    17: attack_17,
}

# --- Attack categories (for the interactive menu) ---
CATEGORIES = {
    "FDI (False Data Injection)":        [1, 6, 8, 10, 11, 13, 16],
    "Command Injection (Unauthorized Control)": [2, 7, 9, 12, 15],
    "DoS (Denial of Service)":           [3, 4, 5],
    "Reconnaissance":                    [14, 17],
}


def print_attack_list():
    """Lists every attack, grouped by category."""
    print()
    print("+" + "-"*68 + "+")
    print("|" + " SCADA-CPS TESTBED - ATTACK LIST".center(68) + "|")
    print("+" + "-"*68 + "+")
    print("|" + f" PLC target: {PLC_IP}:{PLC_PORT}".ljust(68) + "|")
    print("+" + "-"*68 + "+")
    print()

    for category, ids in CATEGORIES.items():
        print(f"  +- {category}")
        for aid in ids:
            name = ATTACK_NAMES.get(aid, "?")
            dur = ATTACK_DURATIONS.get(aid, DEFAULT_ATTACK_DURATION)
            print(f"  |  #{aid:2d} - {name:<35s} [{dur}s = {dur//60}min]")
        print(f"  +{'-'*50}")
        print()


def interactive_menu():
    """Interactive attack-selection menu."""
    print_attack_list()

    print("  Usage: enter an attack number (1-17), or 'q' to quit")
    print()

    while True:
        try:
            choice = input("  Attack # > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            return

        if choice.lower() in ('q', 'quit', 'exit'):
            print("  Exiting.")
            return

        try:
            attack_id = int(choice)
        except ValueError:
            print("  [!] Invalid input. Enter a number between 1 and 17.")
            continue

        if attack_id not in ATTACK_MAP:
            print(f"  [!] Attack #{attack_id} not found. Enter a number between 1 and 17.")
            continue

        # Ask for duration
        default_dur = ATTACK_DURATIONS.get(attack_id, DEFAULT_ATTACK_DURATION)
        dur_input = input(f"  Duration (s) [default: {default_dur}] > ").strip()
        duration = int(dur_input) if dur_input else default_dur

        # Run it
        launch_attack(attack_id, duration, use_label=True)

        print()
        print("-" * 50)
        cont = input("  Run another attack? (y/n) > ").strip().lower()
        if cont not in ('y', 'yes'):
            print("  Exiting.")
            return
        print()


def launch_attack(attack_id, duration, use_label=True):
    """Launches a single attack."""
    name = ATTACK_NAMES.get(attack_id, f"Attack_{attack_id}")
    attack_fn = ATTACK_MAP[attack_id]

    print()
    print("+" + "-"*68 + "+")
    print("|" + f" LAUNCHING ATTACK: #{attack_id} - {name}".ljust(68) + "|")
    print("|" + f" Duration: {duration}s ({duration//60} min {duration%60}s)".ljust(68) + "|")
    print("|" + f" Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".ljust(68) + "|")
    print("+" + "-"*68 + "+")
    print()

    lm = None
    if use_label:
        dataset_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
        lm = LabelManager(output_dir=dataset_dir, plc_ip=PLC_IP, plc_port=PLC_PORT)

    try:
        attack_fn(duration_sec=duration, label_manager=lm)
    except Exception as e:
        print(f"\n  [ERROR] Attack failed: {e}")
        if lm:
            lm.log_attack_end(attack_id, name, f"ERROR: {e}")

    print()
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if lm:
        print(f"  Label file: {lm.get_labels_path()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SCADA-CPS Testbed - Single Attack Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_single_attack.py                        # interactive menu
  python run_single_attack.py --id 1                 # FDI Voltage (default duration)
  python run_single_attack.py --id 3 --duration 120  # Diagnostic Flood, 2 minutes
  python run_single_attack.py --id 14 --duration 300 # Ramp Attack, 5 minutes
  python run_single_attack.py --list                 # list all attacks
  python run_single_attack.py --id 5 --no-label      # unlabeled test run
        """
    )
    parser.add_argument("--id", type=int, default=None,
                        help="Attack ID (1-17)")
    parser.add_argument("--duration", type=int, default=None,
                        help="Attack duration in seconds. Default: from config.py")
    parser.add_argument("--no-label", action="store_true",
                        help="Skip ground-truth labeling (test mode)")
    parser.add_argument("--list", action="store_true",
                        help="List all attacks")

    args = parser.parse_args()

    if args.list:
        print_attack_list()
        sys.exit(0)

    if args.id is None:
        # Interactive menu
        interactive_menu()
    else:
        if args.id not in ATTACK_MAP:
            print(f"[ERROR] Invalid attack ID: {args.id}. Must be between 1 and 17.")
            sys.exit(1)

        duration = args.duration or ATTACK_DURATIONS.get(args.id, DEFAULT_ATTACK_DURATION)
        try:
            launch_attack(args.id, duration, use_label=not args.no_label)
        except KeyboardInterrupt:
            print("\n\n  [!] Attack stopped by user!")
            sys.exit(1)
