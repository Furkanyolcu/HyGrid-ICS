"""
Attack #17: Modbus_Reconnaissance (Modbus Reconnaissance Scan)
===============================================================
Target register: HR0-HR27 (full register map)
Technique: Issues repeated Read Holding Registers (FC03) requests across
           the address range to fingerprint the register map. This is a
           reconnaissance phase, not an active attack.
Effect: Causes no direct damage but increases the PLC's read load; the
        continuous scanning raises latency and shows up to the ML model
        as an "abnormal read pattern" anomaly.
MITRE ATT&CK for ICS: T0846 - Remote System Discovery
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    LABEL_MODBUS_RECON
)

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
SCAN_START  = 0              # Scan start address
SCAN_END    = 100            # Scan end address (wide range)
SCAN_STEP   = 1              # Read every single address
SCAN_DELAY  = 0.05           # 50ms - fast but not DoS-level

ATTACK_NAME = "Modbus_Reconnaissance"
ATTACK_ID   = LABEL_MODBUS_RECON


def run_attack(duration_sec=600, label_manager=None):
    """
    Modbus reconnaissance scan.
    Continuously scans the HR0-HR100 range using FC03 (Read Holding
    Registers) to enumerate the register map. Each round issues 100 reads,
    adding extra load on the PLC.
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT} - HR{SCAN_START}-HR{SCAN_END}")
    print(f"  Scan: {SCAN_END - SCAN_START} registers, {SCAN_DELAY}s interval")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"Scan HR{SCAN_START}-HR{SCAN_END}, interval={SCAN_DELAY}s"
        )

    start_time = time.time()
    packet_count = 0
    found_regs = {}
    scan_round = 0

    try:
        while (time.time() - start_time) < duration_sec:
            scan_round += 1

            for addr in range(SCAN_START, SCAN_END, SCAN_STEP):
                if (time.time() - start_time) >= duration_sec:
                    break
                try:
                    result = client.read_holding_registers(addr, 1)
                    packet_count += 1
                    if not result.isError():
                        val = result.registers[0]
                        if addr not in found_regs:
                            found_regs[addr] = val
                            print(f"  [RECON] Found! HR{addr} = {val}")
                except Exception as e:
                    try:
                        client.close()
                        client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
                        client.connect()
                    except Exception:
                        pass
                    time.sleep(0.5)
                    continue

                time.sleep(SCAN_DELAY)

            # Scan round complete
            elapsed = time.time() - start_time
            remaining = duration_sec - elapsed
            if scan_round % 5 == 0:
                print(f"  [RECON] round #{scan_round} | "
                      f"found: {len(found_regs)} registers | "
                      f"packets: {packet_count} | "
                      f"remaining: {remaining:.0f}s")

    except KeyboardInterrupt:
        print("\n  [RECON] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{scan_round} rounds, {len(found_regs)} registers, {packet_count} packets, {elapsed:.1f}s"
            )

        print(f"\n  [RECON] Reconnaissance finished:")
        print(f"          Rounds: {scan_round}")
        print(f"          Found: {len(found_regs)} active registers")
        print(f"          Packets: {packet_count}")
        print(f"          Duration: {elapsed:.1f}s")

        if found_regs:
            print(f"\n  [RECON] Register map:")
            for addr in sorted(found_regs.keys()):
                print(f"          HR{addr:3d} = {found_regs[addr]}")

        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
