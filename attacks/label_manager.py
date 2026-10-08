"""
SCADA-CPS Testbed - Label Manager
===================================
SCADA adaptation of the labels.csv methodology used in the companion IoT
project.

Independent label-file principle:
- The attacking machine (Kali) writes "attack Y started at time X" to its
  own labels.csv the moment an attack begins.
- The data-collection machine (simulation) has no knowledge of this file.
- Time-series synchronization between the two is performed afterward with
  pandas, during the fusion step.

IMPORTANT - time synchronization:
  Labels read the simulation clock from the PLC's HR6 register. The
  Node-RED CSV logger uses the same sim_time, so both files remain on the
  same time axis.
"""

import csv
import os
import time
from datetime import datetime
from pymodbus.client import ModbusTcpClient


class LabelManager:
    """
    Writes attack ground-truth labels to a CSV file, timestamped using the
    simulation clock (HR6) read back from the PLC.

    Output CSV format:
    sim_time, real_timestamp, attack_id, attack_name, phase, details

    Phase values:
    - START      : attack start
    - END        : attack end
    - NORMAL     : start of a normal-traffic period
    - NORMAL_END : end of a normal-traffic period
    """

    def __init__(self, output_dir="./dataset", plc_ip="192.168.1.3", plc_port=502):
        self.output_dir = output_dir
        self.plc_ip = plc_ip
        self.plc_port = plc_port
        os.makedirs(output_dir, exist_ok=True)

        # Unique filename (run timestamp)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.labels_file = os.path.join(output_dir, f"labels_{ts}.csv")
        self.session_id = ts

        # Simulation day counter (incremented when sim_time wraps 23:xx -> 0:xx)
        self._last_sim_hour = -1
        self._sim_day = 0

        # Create the CSV file and write the header
        with open(self.labels_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "sim_time",           # Simulation clock (HH:MM) - matches the Node-RED CSV
                "sim_day",            # Simulation day counter (disambiguates day wraps)
                "real_timestamp",     # Wall-clock time (secondary correlation)
                "attack_id",          # Numeric attack code
                "attack_name",        # Human-readable attack name
                "phase",              # START / END / NORMAL / NORMAL_END
                "details",            # Additional information
                "session_id",         # Session identifier
            ])

        print(f"[LabelManager] Label file created: {self.labels_file}")
        print(f"[LabelManager] Session ID: {self.session_id}")
        print(f"[LabelManager] PLC: {self.plc_ip}:{self.plc_port} (HR6 sim_time)")

    def _read_sim_time(self):
        """
        Reads the HR6 (simulation clock) register from the PLC.
        HR6 format: HHMM (e.g. 1432 = 14:32)
        Returns a "14:32"-style string.
        """
        try:
            client = ModbusTcpClient(self.plc_ip, port=self.plc_port, timeout=2)
            if client.connect():
                result = client.read_holding_registers(address=6, count=1)
                client.close()

                if not result.isError():
                    raw = result.registers[0]  # HHMM format
                    hh = raw // 100
                    mm = raw % 100

                    # Detect day wraparound (23:xx -> 0:xx transition)
                    if self._last_sim_hour >= 20 and hh <= 3:
                        self._sim_day += 1
                    self._last_sim_hour = hh

                    return f"{hh}:{mm:02d}"
            else:
                client.close()
        except Exception as e:
            print(f"[LabelManager] HR6 read error: {e}")

        # Fallback if the PLC is unreachable
        return "N/A"

    def _write_row(self, attack_id, attack_name, phase, details=""):
        """Writes a single row; sim_time is read live from the PLC."""
        sim_time = self._read_sim_time()
        real_ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

        with open(self.labels_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                sim_time,             # Simulation clock read from the PLC
                self._sim_day,        # Day-wrap counter
                real_ts,              # Wall-clock time (secondary)
                attack_id,
                attack_name,
                phase,
                details,
                self.session_id,
            ])

    def log_attack_start(self, attack_id, attack_name, details=""):
        """Logs the start of an attack."""
        self._write_row(attack_id, attack_name, "START", details)
        sim = self._read_sim_time()
        print(f"[LabelManager] ATTACK STARTED: {attack_name} (ID={attack_id})")
        print(f"[LabelManager]    Sim time: {sim} | Day: {self._sim_day}")

    def log_attack_end(self, attack_id, attack_name, details=""):
        """Logs the end of an attack."""
        self._write_row(attack_id, attack_name, "END", details)
        sim = self._read_sim_time()
        print(f"[LabelManager] ATTACK ENDED:   {attack_name} (ID={attack_id})")
        print(f"[LabelManager]    Sim time: {sim} | Day: {self._sim_day}")

    def log_normal_start(self, details=""):
        """Logs the start of a normal-traffic period."""
        self._write_row(0, "Normal", "NORMAL", details)
        print(f"[LabelManager] NORMAL TRAFFIC started (Sim: {self._read_sim_time()})")

    def log_normal_end(self, details=""):
        """Logs the end of a normal-traffic period."""
        self._write_row(0, "Normal", "NORMAL_END", details)
        print(f"[LabelManager] NORMAL TRAFFIC ended (Sim: {self._read_sim_time()})")

    def get_labels_path(self):
        """Returns the path to the label file."""
        return self.labels_file
