"""
SCADA-CPS Testbed - Physical Attack Configuration
===================================================
Shared configuration for all physical (Modbus/TCP) attack scripts:
PLC connection details, holding-register map, and timing constants.

Timing reference:
  LOOP_INTERVAL = 100ms -> 10 rows/second (synchronized with the Node-RED
  CSV logger, which records at the same 100ms cadence).
"""

# ---------------------------------------------------------------------------
# Network settings
# ---------------------------------------------------------------------------
PLC_IP   = "192.168.1.3"   # VM3 - OpenPLC
PLC_PORT = 502             # Modbus-TCP port
UNIT_ID  = 1               # Modbus unit ID (slave ID)

# ---------------------------------------------------------------------------
# Modbus holding-register map
# ---------------------------------------------------------------------------
# Control registers (HMI -> PLC -> simulation)
HR0_LOAD_SHED   = 0    # 0=Normal, 1=Shed residential load
HR1_CAPACITOR   = 1    # 0=Off, 1=On
HR2_SOLAR_LIMIT = 2    # 0-100 (%)
HR3_BATTERY     = 3    # 0=Standby, 1=Discharge, 2=Charge

# Sensor registers (simulation -> PLC -> HMI)
HR4_FREQ        = 4    # Frequency (x100) -> 5002 = 50.02 Hz
HR5_MIN_VOLTAGE = 5    # Min voltage (x1000) -> 965 = 0.965 p.u.
HR6_SIM_TIME    = 6    # Simulation clock (HHMM)
HR7_ALARM       = 7    # Alarm flag (0/1)
HR8_V_SUB       = 8    # Substation bus voltage (x1000)
HR9_V_IND       = 9    # Industrial bus voltage (x1000)
HR10_V_RES      = 10   # Residential bus voltage (x1000)
HR11_V_COM      = 11   # Commercial bus voltage (x1000)
HR12_TOTAL_KW   = 12   # Total active load (kW)
HR13_LOSSES     = 13   # Line losses (x10)
HR14_SOLAR_KW   = 14   # Solar generation (x10)
HR15_LATENCY    = 15   # PLC latency (x100)

# Phase-5 additional registers
HR16_T_OIL      = 16   # Transformer oil temperature, degC (x10)
HR17_T_HOTSPOT  = 17   # Transformer hotspot temperature, degC (x10)
HR18_T_AMBIENT  = 18   # Ambient temperature, degC (x10)
HR19_COOLING    = 19   # Cooling mode (0=ONAN, 1=ONAF)
HR20_SOC        = 20   # Battery state of charge (%)
HR21_T_BATTERY  = 21   # Battery temperature, degC (x10)
HR22_IRRADIANCE = 22   # Solar irradiance (W/m^2)
HR23_WIND       = 23   # Wind speed (x10)
HR24_PROT_MASK  = 24   # Protection relay bitmask
HR25_AGING      = 25   # Transformer aging rate (x100)
HR26_SOH        = 26   # Battery state of health (%)
HR27_CLOUD      = 27   # Cloud coverage (%)

# ---------------------------------------------------------------------------
# Timing constants
# ---------------------------------------------------------------------------
# Base cadence: 100ms - the main simulation loop, every attack script, and
# the Node-RED CSV logger all operate at the same sampling rate.
LOOP_INTERVAL       = 0.1    # 100ms - main simulation loop
ATTACK_LOOP_DELAY   = 0.1    # 100ms - attack loop (same cadence)

# Baseline and inter-attack rest periods
# 100ms polling -> 10 rows/second
# Target distribution: Normal >= 40%, ~10,000-15,000 rows per attack class
NORMAL_DURATION_SEC = 180   # 30 min baseline -> ~108,000 rows
BREAK_DURATION      = 600    # 10 min rest between attacks -> ~36,000 rows
DEFAULT_ATTACK_DURATION = 1000  # Default attack duration -> ~10,000 rows

# Per-attack durations (seconds)
# DoS/fuzzing attacks keep the PLC busy and cause missed polling cycles,
# so these scenarios are run slightly longer to compensate for data loss.
ATTACK_DURATIONS = {
    1:  1000,   # FDI Voltage              -> ~10,000 rows (passive, no loss)
    2:  1200,   # Coil Manipulation        -> ~10,200 rows (15% loss compensation)
    3:  1500,   # Diagnostic Flood         -> ~11,250 rows (25% loss compensation)
    4:  1300,   # Illegal Address          -> ~10,400 rows (20% loss compensation)
    5:  1200,   # Function Code Fuzzing    -> ~10,200 rows (15% loss compensation)
    6:  1000,   # Load Shedding Sabotage   -> ~10,000 rows
    7:  1000,   # Generation Overload      -> ~10,000 rows
    8:  1000,   # Voltage Instability      -> ~10,000 rows
    9:  1000,   # Battery Drain            -> ~10,000 rows
    10: 1000,   # Thermal Sabotage         -> ~10,000 rows
    11: 1000,   # Frequency Desync         -> ~10,000 rows
    12: 1000,   # Reactive Power           -> ~10,000 rows
    13: 1000,   # Bus Overload             -> ~10,000 rows
    14: 1500,   # Ramp Attack              -> ~15,000 rows (very passive, compensated)
    15: 1000,   # Impossible State         -> ~10,000 rows
    16: 1000,   # False Alarm Injection    -> ~10,000 rows
    17: 1000,   # Modbus Reconnaissance    -> ~10,000 rows
}

# ---------------------------------------------------------------------------
# Attack labels (for labels.csv)
# ---------------------------------------------------------------------------
LABEL_NORMAL                = 0
LABEL_FDI_VOLTAGE           = 1
LABEL_COIL_MANIPULATION     = 2
LABEL_DIAG_FLOOD            = 3
LABEL_ILLEGAL_ADDRESS       = 4
LABEL_FC_FUZZING            = 5
LABEL_LOAD_SABOTAGE         = 6
LABEL_GENERATION_OVERLOAD   = 7
LABEL_VOLTAGE_INSTABILITY   = 8
LABEL_BATTERY_DRAIN         = 9
LABEL_THERMAL_SABOTAGE      = 10
LABEL_FREQ_DESYNC           = 11
LABEL_REACTIVE_POWER        = 12
LABEL_BUS_OVERLOAD          = 13
LABEL_RAMP_ATTACK           = 14
LABEL_LOGIC_FLAW            = 15
LABEL_FALSE_ALARM           = 16
LABEL_MODBUS_RECON          = 17

ATTACK_NAMES = {
    0:  "Normal",
    1:  "FDI_Voltage_Injection",
    2:  "Coil_Manipulation_FC05",
    3:  "Diagnostic_Flood_FC08",
    4:  "Illegal_Address_Injection",
    5:  "Function_Code_Fuzzing",
    6:  "Load_Shedding_Sabotage",
    7:  "Generation_Overload",
    8:  "Voltage_Instability",
    9:  "Battery_Drain_Attack",
    10: "Thermal_Sabotage",
    11: "Frequency_Desync",
    12: "Reactive_Power_Manipulation",
    13: "Bus_Overload_FDI",
    14: "Ramp_Attack",
    15: "Impossible_State_Injection",
    16: "False_Alarm_Injection",
    17: "Modbus_Reconnaissance",
}
