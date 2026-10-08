# HyGrid-ICS Dataset - Technical Notes

---

## About this dataset

This dataset was collected on a real-hardware SCADA cyber-physical system (CPS)
testbed. It is a **hybrid** dataset combining physical process telemetry
(OpenDSS + Modbus/PLC) and network traffic (Zeek IDS). The notes below are
important for correctly interpreting the data.

---

## Not a bug - physical realism

### 1. `freq_hz` - normal range 49.0-50.5 Hz

- **Normal traffic:** 49.5-50.2 Hz (small oscillations - genuine power-system behavior)
- **Frequency_Desync attack:** 45.0 Hz (HR4=4500 written from Kali; Node-RED reads 4500/100=45.0)
- A few other attacks may also show freq=45 or 49.x - the attack changes the
  physical model's (swing-equation) frequency response
- `freq_hz` is computed by Node-RED as `HR4_register / 100`

### 2. `T_oil` - normal range 39-85 degC (never 0 degC)

- **Normal traffic:** 39-60 degC (transformer running cool/warm)
- **Thermal_Sabotage attack:** 90 degC (HR16=900, Node-RED reads 900/10=90)
- There are no zero values for T_oil in this dataset - that was a defect in an
  earlier version, fixed in v1.5

### 3. `T_hotspot` - normal range 47-105 degC

- Modeled per IEC 60076-7
- **Thermal_Sabotage:** 120 degC (HR17=1200, Node-RED reads 1200/10=120)
  - Note: the sudden jump (e.g. 87.8 degC -> 120.0 degC) does not represent a
    real thermal transient - it is a false-data-injection (FDI) attack where
    the attacker directly overwrites the PLC register, producing a fake
    thermal-emergency reading on the HMI.
- Forced cooling (ONAN -> ONAF transition) engages above T_hotspot > 70 degC,
  reflected in the `cooling_mode` column

### 4. `total_kw` - real range 0-2200 kW

- The transformer's rated capacity is 4500 kW, but the OpenDSS load profiles
  vary between 200-2200 kW depending on time of day
- The "0-4500 kW" figure elsewhere refers to transformer capacity, not the
  actual load profile

### 5. `losses_kw` - 17-125 kW (can look disproportionate to load)

- This is OpenDSS's `Circuit.Losses()` output: **total circuit losses**
  = transformer no-load (core) loss + copper loss + line loss
- A 4500 kVA transformer's no-load loss is ~15-30 kW and is present
  continuously, independent of load
- `losses_kw` and `total_kw` are therefore not directly proportional
- Reference: IEC 60076-1 distinction between "no-load loss" and "load loss"

### 6. `solar_kw` - ~0 kW at night (0-0.1 kW)

- At night (irradiance ~0 W/m^2), solar_kw ~= 0.0
- Small fractional values (0.1, 0.2 kW) can appear during day/night transitions
  due to 200 ms window averaging - this is physically correct
- **Impossible_State_Injection attack:** solar_kw = 999.9 kW (HR14=9999, a
  physically impossible value given the 400 kW panel capacity)

### 7. `irradiance` - 0-1100 W/m^2

- Night: 0-2 W/m^2 (moonlight + stray light)
- Day: 200-1000 W/m^2
- Extreme heat + clear sky: 1100 W/m^2 (maximum - Generation_Overload scenario)
- Values between 0 and 1 reflect 200 ms window averages during day/night transitions

### 8. `prot_bitmask` - integer (0-1023)

- A 10-bit protection-system status bitmask; aggregated within each 200 ms
  window using **bitwise OR**
- Not `mean()` - OR means any bit set during the window is recorded as set

---

## Known limitations

### 9. ICMP_Flood and UDP_Flood - Zeek signature and low-rate DDoS

- Early versions of these flood attacks crashed the HMI hardware (Raspberry Pi),
  causing data loss (gaps). To prevent this, both attacks were converted to a
  **low-rate DDoS** profile (~50 pkt/s).
- Because of the reduced rate, Zeek's network statistics (packet/byte counts)
  for these classes can sit close to Normal traffic. Physical-feature anomalies,
  rather than Zeek features, are the more reliable signal for separating these
  classes from Normal.
- **ICMP_Flood specifically:** because raw ICMP traffic (sent via raw sockets)
  is not fully captured by Zeek's connection-oriented `conn.log` the way
  TCP/UDP traffic is, this class shows an especially weak network-layer
  signature across all 11 released network features. This is a genuine
  instrumentation limitation of connection-state-based monitoring for
  connectionless flood traffic, not a labeling error - the attack script did
  run as intended for every row labeled ICMP_Flood.

### 10. TCP_SYN_Flood and TCP_ACK_Flood - few rows

- These floods generate a very high number of short-lived connections; since
  Zeek coalesces some half-open connections, the row count per 200 ms window
  is roughly 30-76.
- `zeek_s0_count` (unanswered SYN) and `zeek_rej_count` are the most
  discriminative features for classifying these attacks.

### 11. `data_gap = 1` rows

- Gaps longer than 1 second in the time series (network delay, system load)
  are filled forward.
- Rows with `data_gap = 1` mark the first row affected by this fill.
- Sequence models (LSTM, GRU) should take this flag into account.

### 12. `Impossible_State_Injection` - comparatively many rows

- This attack injects HR14=9999 (solar=999.9 kW) - a physically impossible
  generation value.
- The fusion script also reassigns Normal-labeled rows with `solar_kw > 990`
  into this class (to resolve overlapping timestamps at the attack boundary).
- This is why this class has somewhat more rows than most others.

### 13. `APT_Exfiltration` - low `zeek_orig_bytes`

- This attack produces slow data-exfiltration traffic from Kali to the
  Raspberry Pi.
- Because Zeek runs on the Pi's network interface, it records the **incoming**
  direction; data sent by the attacker (Kali -> Pi) appears in Zeek as
  `resp_bytes`, not `orig_bytes`.
- `zeek_orig_bytes` can therefore look low for this class.
- **Recommended features for this class:** `latency_ms` (increased delay),
  `zeek_conn_count` (many short connections), `zeek_duration_mean`, and
  Modbus read frequency.
- This is an architectural property of the monitoring setup (a sensor on the
  internal network sees attacker-sent traffic as "incoming"), consistent with
  a realistic passive-IDS deployment.

### 14. `Battery_Drain_Attack` - SoC starts over in two sessions

- The dataset was merged from two separate simulation sessions.
- In the first session, the Battery_Drain attack reduced SoC from 90 to 5.
- In the second session, the system restarted with SoC at 80.
- Sorting by `timestamp` reveals two distinct sessions; each is internally
  monotonic and consistent.

### 15. `losses_kw` > `total_kw` - reactive-loss dominance at low load

- This system models the combined reactive losses of the 4500 kVA transformer
  and distribution lines.
- Normal-class mean `losses_kw` is ~68.7 kW, consistent with this model.
- At low load (`total_kw` = 38-51 kW), `losses_kw` can remain roughly constant
  - a known phenomenon ("low-load reactive loss dominance", combined
  no-load + load loss per IEC 60076).
- This pattern appears in ~0.013% of all rows and is physically valid.

### 16. `Vulnerability_Scan` - shortened recording duration

- A network interruption cut this scenario's recording short, to ~18.5
  minutes (target: 25 minutes).
- Result: Vulnerability_Scan has 5,541 samples, versus 7,421-7,787 for the
  other classes (~26% fewer).
- `class_weight='balanced'` is recommended to compensate during training.

### 17. `Frequency_Desync` -> `Reactive_Power_Manipulation` transition contamination

- These two scenarios were run back-to-back in the experiment schedule, with
  no intervening normal/rest period.
- Grid frequency follows the swing equation and therefore has real inertia:
  it does not reset instantaneously once Frequency_Desync's injected 45.0 Hz
  value stops being written.
- As a result, approximately 99% of the rows labeled
  `Reactive_Power_Manipulation` also carry a residual `freq_hz = 45.0`
  signature inherited from the preceding scenario, settling back toward the
  normal range only in the final rows of the window.
- This does **not** affect the validity of this class's own intended signature:
  `HR1` (capacitor forced on) and `min_voltage` (forced to ~0.91 p.u.) are
  present and correct in 100% of rows. However, a classifier trained on this
  data may partly key on the inherited frequency artifact rather than the
  scenario's true cause. This is disclosed here rather than corrected in the
  data, since the "true" uncontaminated frequency trajectory cannot be
  reconstructed after the fact without re-running the scenario with a
  settling period inserted between the two attacks.

---

## Unit scaling (Node-RED -> CSV)

| Register | Stored in PLC as | Converted to CSV as | Example |
|---|---|---|---|
| `freq_hz` | HR4 = Hz x 100 | HR4 / 100 | 4983 -> 49.83 Hz |
| `min_voltage` | HR5 = p.u. x 1000 | HR5 / 1000 | 983 -> 0.983 p.u. |
| `v_sub/ind/res/com` | HR8-11 = p.u. x 1000 | HR / 1000 | 1022 -> 1.022 p.u. |
| `total_kw` | HR12 = kW (integer) | direct | 1247 -> 1247 kW |
| `losses_kw` | HR13 = kW x 10 | HR13 / 10 | 631 -> 63.1 kW |
| `solar_kw` | HR14 = kW x 10 | HR14 / 10 | 4000 -> 400.0 kW |
| `T_oil` | HR16 = degC x 10 | HR16 / 10 | 397 -> 39.7 degC |
| `T_hotspot` | HR17 = degC x 10 | HR17 / 10 | 521 -> 52.1 degC |
| `irradiance` | HR22 = W/m^2 (integer) | direct | 697 -> 697 W/m^2 |
| `SoC` | HR20 = % (integer) | direct | 79 -> 79% |

---

## System topology

```
Raspberry Pi 4B               OpenPLC Runtime v3
  main_sim.py    --Modbus-->  192.168.1.3:502
  (OpenDSS)                        |
                            Node-RED HMI
                            (CSV logging @ 5 Hz)
                                   |
                            Kali Linux attack machine
                            masterrunner.py -> 29 attacks
                            Zeek IDS -> conn.log, modbus.log
```

---

## Recommended usage

```python
import pandas as pd

df = pd.read_csv('scada_cps_dataset.csv')

# Binary classification: Normal=0, Attack=1
y = df['Is_Attack']

# Multi-class classification: 30 classes (Normal + 29 attack types)
y = df['Attack_Type']

# Feature groups
PHYSICAL = ['freq_hz','min_voltage','total_kw','solar_kw','losses_kw',
            'alarm','v_sub','v_ind','v_res','v_com','T_oil','T_hotspot',
            'T_ambient','cooling_mode','SoC','SoH','T_battery',
            'irradiance','wind_speed','prot_bitmask','aging_rate',
            'HR0','HR1','HR2','HR3']
NETWORK  = ['zeek_conn_count','zeek_orig_bytes','zeek_resp_bytes',
            'zeek_orig_pkts','zeek_resp_pkts','zeek_duration_mean',
            'zeek_rej_count','zeek_s0_count','zeek_modbus_pkts']

# Handle data_gap=1 rows carefully in sequence models
df_clean = df[df['data_gap'] == 0]  # contiguous time windows only
```

---

## Dataset summary

| Property | Value |
|---|---|
| Version | v-final |
| Total samples | 433,568 |
| Feature count | 38 (27 physical + 11 network) |
| Class count | 30 (1 Normal + 29 attacks) |
| Missing values | 0 |
| Sampling rate | ~5 Hz (200 ms) |
| PLC protocol | Modbus-TCP (OpenPLC Runtime v3) |
| Power system | OpenDSS - 5-bus microgrid, 4500 kVA transformer |
| Attack framework | MITRE ATT&CK for ICS |
| Collection duration | ~24 hours |
