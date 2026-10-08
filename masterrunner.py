#!/usr/bin/env python3
"""
SCADA-CPS Testbed - Master Attack Orchestrator v2.0
=====================================================
Runs both physical (Modbus) and network attacks automatically and
sequentially, back-to-back. 29 attacks in total.

Flow (per attack):
  [baseline] -> [attack] -> [recovery]

Usage:
  python masterrunner.py                        # all attacks, 30s test mode
  python masterrunner.py --attack-time 600      # all attacks, 10 min each
  python masterrunner.py --baseline 30          # baseline duration (s)
  python masterrunner.py --only-network         # network attacks only
  python masterrunner.py --only-physical        # physical attacks only
  python masterrunner.py --zeek                 # start/stop Zeek automatically
  python masterrunner.py --zeek-iface eth0      # Zeek listening interface

Zeek note:
  With --zeek, this script starts Zeek under the project's zeek_logs/
  directory and keeps it running as a single process for the entire
  attack session, stopping it cleanly before exiting so the logs are
  preserved.
"""

import sys
import os
import time
import argparse
import subprocess
import signal
from datetime import datetime, timedelta

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attacks.label_manager import LabelManager
from attacks.config import (
    PLC_IP, PLC_PORT,
    DEFAULT_ATTACK_DURATION, ATTACK_DURATIONS,
    NORMAL_DURATION_SEC, ATTACK_NAMES
)
from network_attacks.net_config import (
    NETWORK_ATTACK_NAMES, NET_DURATIONS, DEFAULT_NET_DURATION
)

# ---------------------------------------------------------------------------
# Physical attack modules
# ---------------------------------------------------------------------------
from attacks.attack_01_fdi_voltage      import run_attack as attack_01
from attacks.attack_02_coil_manipulation import run_attack as attack_02
from attacks.attack_03_diag_flood       import run_attack as attack_03
from attacks.attack_04_illegal_address  import run_attack as attack_04
from attacks.attack_05_fc_fuzzing       import run_attack as attack_05
from attacks.attack_06_load_sabotage    import run_attack as attack_06
from attacks.attack_07_gen_overload     import run_attack as attack_07
from attacks.attack_08_voltage_instability import run_attack as attack_08
from attacks.attack_09_battery_drain    import run_attack as attack_09
from attacks.attack_10_thermal_sabotage import run_attack as attack_10
from attacks.attack_11_freq_desync      import run_attack as attack_11
from attacks.attack_12_reactive_power   import run_attack as attack_12
from attacks.attack_13_bus_overload     import run_attack as attack_13
from attacks.attack_14_ramp_attack      import run_attack as attack_14
from attacks.attack_15_impossible_state import run_attack as attack_15
from attacks.attack_16_false_alarm      import run_attack as attack_16
from attacks.attack_17_modbus_recon     import run_attack as attack_17

# ---------------------------------------------------------------------------
# Network attack modules
# ---------------------------------------------------------------------------
from network_attacks.attack_net_01_icmp_flood    import run_attack as net_01
from network_attacks.attack_net_02_udp_flood     import run_attack as net_02
from network_attacks.attack_net_03_tcp_syn_flood import run_attack as net_03
from network_attacks.attack_net_04_tcp_ack_flood import run_attack as net_04
from network_attacks.attack_net_05_http_flood    import run_attack as net_05
from network_attacks.attack_net_06_port_scan     import run_attack as net_06
from network_attacks.attack_net_07_os_scan       import run_attack as net_07
from network_attacks.attack_net_08_vuln_scan     import run_attack as net_08
from network_attacks.attack_net_09_nodered_injection import run_attack as net_09
from network_attacks.attack_net_10_insider_threat import run_attack as net_10
from network_attacks.attack_net_11_apt_exfil     import run_attack as net_11
from network_attacks.attack_net_12_modbus_abuse  import run_attack as net_12

# ---------------------------------------------------------------------------
# Attack sequences
# ---------------------------------------------------------------------------
PHYSICAL_SEQUENCE = [
    (1,  attack_01, "FDI_Voltage_Injection"),
    (2,  attack_02, "Coil_Manipulation_FC05"),
    (3,  attack_03, "Diagnostic_Flood_FC08"),
    (4,  attack_04, "Illegal_Address_Injection"),
    (5,  attack_05, "Function_Code_Fuzzing"),
    (6,  attack_06, "Load_Shedding_Sabotage"),
    (7,  attack_07, "Generation_Overload"),
    (8,  attack_08, "Voltage_Instability"),
    (9,  attack_09, "Battery_Drain_Attack"),
    (10, attack_10, "Thermal_Sabotage"),
    (11, attack_11, "Frequency_Desync"),
    (12, attack_12, "Reactive_Power_Manipulation"),
    (13, attack_13, "Bus_Overload_FDI"),
    (14, attack_14, "Ramp_Attack"),
    (15, attack_15, "Impossible_State_Injection"),
    (16, attack_16, "False_Alarm_Injection"),
    (17, attack_17, "Modbus_Reconnaissance"),
]

NETWORK_SEQUENCE = [
    (101, net_01, "icmp_flood",        NETWORK_ATTACK_NAMES[101]),
    (102, net_02, "udp_flood",         NETWORK_ATTACK_NAMES[102]),
    (103, net_03, "tcp_syn_flood",     NETWORK_ATTACK_NAMES[103]),
    (104, net_04, "tcp_ack_flood",     NETWORK_ATTACK_NAMES[104]),
    (105, net_05, "http_flood",        NETWORK_ATTACK_NAMES[105]),
    (106, net_06, "port_scan",         NETWORK_ATTACK_NAMES[106]),
    (107, net_07, "os_scan",           NETWORK_ATTACK_NAMES[107]),
    (108, net_08, "vuln_scan",         NETWORK_ATTACK_NAMES[108]),
    (109, net_09, "nodered_injection", NETWORK_ATTACK_NAMES[109]),
    (110, net_10, "insider_threat",    NETWORK_ATTACK_NAMES[110]),
    (111, net_11, "apt_exfil",         NETWORK_ATTACK_NAMES[111]),
    (112, net_12, "modbus_abuse",      NETWORK_ATTACK_NAMES[112]),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bar(elapsed, total, width=40):
    """Text progress bar."""
    pct = min(elapsed / total, 1.0) if total > 0 else 0
    filled = int(width * pct)
    bar = "#" * filled + "." * (width - filled)
    return f"[{bar}] {pct*100:.0f}%"


def wait_with_bar(seconds, label="Waiting"):
    """Waits for the given duration, printing a countdown progress bar."""
    print(f"\n  {label}: starting {seconds}s wait...")
    start = time.time()
    try:
        while True:
            elapsed = time.time() - start
            if elapsed >= seconds:
                break
            remaining = seconds - elapsed
            bar = _bar(elapsed, seconds)
            print(f"\r  {label} {bar} remaining: {remaining:.0f}s  ",
                  end="", flush=True)
            time.sleep(0.5)
    except KeyboardInterrupt:
        raise
    finally:
        print()   # newline


def print_master_banner(total_attacks, total_est_sec):
    eta = datetime.now() + timedelta(seconds=total_est_sec)
    print()
    print("+" + "-"*65 + "+")
    print("|" + " SCADA-CPS TESTBED - MASTER ORCHESTRATOR v2.0".center(65) + "|")
    print("+" + "-"*65 + "+")
    print("|" + f"  Total attacks    : {total_attacks}".ljust(65) + "|")
    print("|" + f"  Estimated time   : ~{total_est_sec//60} min".ljust(65) + "|")
    print("|" + f"  Estimated finish : {eta.strftime('%H:%M:%S')}".ljust(65) + "|")
    print("|" + f"  PLC target       : {PLC_IP}:{PLC_PORT}".ljust(65) + "|")
    print("|" + f"  Started at       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".ljust(65) + "|")
    print("+" + "-"*65 + "+")
    print()


def print_section(title):
    print()
    print("*"*67)
    print(f"  {title}")
    print("*"*67)
    print()


def print_attack_header(idx, total, attack_id, attack_name, duration, phase="ATTACK"):
    print()
    print("-"*67)
    print(f"  [{idx}/{total}] {phase}: #{attack_id} - {attack_name}")
    print(f"       Duration: {duration}s | Start: {datetime.now().strftime('%H:%M:%S')}")
    print("-"*67)


# ---------------------------------------------------------------------------
# Zeek management
# ---------------------------------------------------------------------------

_zeek_proc = None


def _find_zeek():
    """
    Locates the Zeek binary.
    Checks PATH first, then falls back to known install locations.
    """
    import shutil
    z = shutil.which("zeek")
    if z:
        return z
    candidates = [
        "/usr/local/zeek/bin/zeek",   # default Kali install location
        "/opt/zeek/bin/zeek",
        "/usr/bin/zeek",
        "/usr/local/bin/zeek",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def start_zeek(iface="eth0", log_dir=None):
    """
    Starts Zeek in the background.
    Logs are written to log_dir because Zeek has no -l flag; it writes
    to its current working directory, so log_dir is used as cwd.
    """
    global _zeek_proc
    if log_dir is None:
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zeek_logs")
    os.makedirs(log_dir, exist_ok=True)

    zeek_bin = _find_zeek()
    if zeek_bin is None:
        print("  [!] Zeek binary not found!")
        print("      Checked paths: /usr/local/zeek/bin/zeek, /opt/zeek/bin/zeek")
        print("      Fix: export PATH=$PATH:/usr/local/zeek/bin")
        return False

    cmd = [zeek_bin, "-i", iface]
    try:
        _zeek_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=log_dir,             # logs are written here
            preexec_fn=os.setsid
        )
        time.sleep(2)   # give Zeek time to start
        if _zeek_proc.poll() is None:
            print(f"  [OK] Zeek started (PID={_zeek_proc.pid})")
            print(f"       Binary : {zeek_bin}")
            print(f"       Logdir : {log_dir}")
            return True
        else:
            print("  [!] Zeek failed to start (process exited immediately)")
            print(f"      Command: {zeek_bin} -i {iface}")
            _zeek_proc = None
            return False
    except FileNotFoundError:
        print(f"  [!] Zeek binary not found: {zeek_bin}")
        _zeek_proc = None
        return False
    except Exception as e:
        print(f"  [!] Error starting Zeek: {e}")
        _zeek_proc = None
        return False


def stop_zeek():
    """Stops Zeek."""
    global _zeek_proc
    if _zeek_proc is not None:
        try:
            os.killpg(os.getpgid(_zeek_proc.pid), signal.SIGTERM)
            _zeek_proc.wait(timeout=5)
            print("  [OK] Zeek stopped.")
        except Exception as e:
            print(f"  [!] Error stopping Zeek: {e}")
        finally:
            _zeek_proc = None


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_all(
    attack_time,
    baseline_sec,
    recovery_sec,
    only_network=False,
    only_physical=False,
    use_zeek=False,
    zeek_iface="eth0",
    zeek_log_dir=None,
):
    """
    Runs every attack sequentially, back-to-back.

    Flow per attack:
      [baseline_sec BASELINE] -> [attack_time ATTACK] -> [recovery_sec RECOVERY]
    """
    if zeek_log_dir is None:
        zeek_log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zeek_logs")

    # Which sequences will run?
    sequences = []
    if not only_network:
        sequences.append(("PHYSICAL", PHYSICAL_SEQUENCE, "physical"))
    if not only_physical:
        sequences.append(("NETWORK", NETWORK_SEQUENCE, "network"))

    total_attacks = sum(len(s) for _, s, _ in sequences)

    # Rough total-time estimate: one initial baseline + attack duration per
    # scenario + a short cooldown between scenarios.
    cooldown_sec = 2
    total_est = baseline_sec + (total_attacks * attack_time) + (total_attacks * cooldown_sec)

    print_master_banner(total_attacks, total_est)

    # Start Zeek
    if use_zeek:
        print_section("STARTING ZEEK")
        start_zeek(iface=zeek_iface, log_dir=zeek_log_dir)

    # LabelManager - single session, all attacks write to the same file
    dataset_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
    lm = LabelManager(output_dir=dataset_dir, plc_ip=PLC_IP, plc_port=PLC_PORT)

    # --- Initial baseline (once, at the very start) -----------------------
    if baseline_sec > 0:
        print_section(f"INITIAL BASELINE (NORMAL TRAFFIC): {baseline_sec}s")
        lm.log_normal_start("Initial global baseline normal traffic")
        wait_with_bar(baseline_sec, "GLOBAL BASELINE")
        lm.log_normal_end("Initial global baseline complete")

    global_idx = 0   # counter across all attacks

    try:
        for phase_name, sequence, seq_type in sequences:
            print_section(f"PHASE: {phase_name} ATTACKS ({len(sequence)} total)")

            for local_idx, entry in enumerate(sequence, 1):
                global_idx += 1

                if seq_type == "physical":
                    attack_id, attack_fn, attack_name = entry
                    duration = attack_time  # fixed in test mode
                else:
                    # network: (id, fn, key, name)
                    attack_id, attack_fn, duration_key, attack_name = entry
                    if attack_time != DEFAULT_ATTACK_DURATION:
                        duration = attack_time
                    else:
                        duration = NET_DURATIONS.get(duration_key, DEFAULT_NET_DURATION)

                # --- Attack phase -----------------------------------------
                print_attack_header(
                    global_idx, total_attacks,
                    attack_id, attack_name,
                    duration, "ATTACK"
                )
                try:
                    attack_fn(
                        duration_sec=duration,
                        label_manager=lm
                    )
                except Exception as e:
                    print(f"\n  [ERROR] Attack failed: {e}")
                    lm.log_attack_end(attack_id, attack_name, f"ERROR: {e}")

                # --- Cooldown between attacks -------------------------------
                if global_idx < total_attacks:
                    print(f"\n  Short cooldown between attacks: {cooldown_sec}s...")
                    time.sleep(cooldown_sec)

    except KeyboardInterrupt:
        print("\n\n  [!] Master orchestrator stopped by user!")
    finally:
        if use_zeek:
            print_section("STOPPING ZEEK")
            stop_zeek()

    # --- Summary ------------------------------------------------------------
    print()
    print("+" + "-"*65 + "+")
    print("|" + "  ALL ATTACKS COMPLETE".center(65) + "|")
    print("+" + "-"*65 + "+")
    print("|" + f"  Completed    : {global_idx}/{total_attacks} attacks".ljust(65) + "|")
    print("|" + f"  Label file   : {lm.get_labels_path()}"[:65].ljust(65) + "|")
    print("|" + f"  Finished at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".ljust(65) + "|")
    if use_zeek:
        print("|" + f"  Zeek logs    : {zeek_log_dir}".ljust(65) + "|")
    print("+" + "-"*65 + "+")
    print()
    print("  Next steps:")
    print("  1. Export the physical telemetry CSV (Node-RED / InfluxDB).")
    print("  2. Process the Zeek logs: zeek-cut ts id.orig_h ... < conn.log")
    print("  3. Run the fusion script to merge physical and network logs.")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SCADA-CPS Testbed - Master Attack Orchestrator v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 30-second test run (per attack: 30s baseline + 30s attack + 30s recovery)
  python masterrunner.py --attack-time 30

  # Full 10-minute production run
  python masterrunner.py --attack-time 600 --baseline 30 --recovery 30

  # Network attacks only, with Zeek
  python masterrunner.py --attack-time 600 --only-network --zeek --zeek-iface eth0

  # Physical attacks only
  python masterrunner.py --attack-time 600 --only-physical
        """
    )
    parser.add_argument(
        "--attack-time", type=int, default=30,
        help="Duration of each attack in seconds. 30 for testing, 600 for production. [default: 30]"
    )
    parser.add_argument(
        "--baseline", type=int, default=30,
        help="Normal-traffic duration BEFORE each attack, in seconds. [default: 30]"
    )
    parser.add_argument(
        "--recovery", type=int, default=30,
        help="Normal-traffic duration AFTER each attack, in seconds. [default: 30]"
    )
    parser.add_argument(
        "--only-network", action="store_true",
        help="Run only the 12 network attacks."
    )
    parser.add_argument(
        "--only-physical", action="store_true",
        help="Run only the 17 physical Modbus attacks."
    )
    parser.add_argument(
        "--zeek", action="store_true",
        help="Start Zeek automatically and stop it when the run finishes."
    )
    parser.add_argument(
        "--zeek-iface", type=str, default="eth0",
        help="Network interface for Zeek to listen on. [default: eth0]"
    )
    parser.add_argument(
        "--zeek-log-dir", type=str, default=None,
        help="Zeek log directory. [default: zeek_logs/ under the project directory]"
    )

    args = parser.parse_args()

    if args.only_network and args.only_physical:
        print("[ERROR] --only-network and --only-physical cannot be used together!")
        sys.exit(1)

    try:
        run_all(
            attack_time=args.attack_time,
            baseline_sec=args.baseline,
            recovery_sec=args.recovery,
            only_network=args.only_network,
            only_physical=args.only_physical,
            use_zeek=args.zeek,
            zeek_iface=args.zeek_iface,
            zeek_log_dir=args.zeek_log_dir,
        )
    except KeyboardInterrupt:
        print("\n\n  [!] Stopped by user!")
        if _zeek_proc:
            stop_zeek()
        sys.exit(1)


if __name__ == "__main__":
    main()
