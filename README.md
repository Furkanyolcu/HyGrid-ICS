# HyGrid-ICS

## A Hybrid Cyber-Physical Security Dataset for SCADA-Based Industrial Control Systems

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23250468.svg)](https://doi.org/10.5281/zenodo.23250468)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![OpenDSS](https://img.shields.io/badge/Simulator-OpenDSS-green.svg)](https://sourceforge.net/projects/electricdss/)

This repository contains the testbed code, attack scripts, Zeek network-monitoring configuration, and Node-RED flow used to generate the **HyGrid-ICS** dataset, companion to the paper *"HyGrid-ICS: A Multi-Class Cyber-Physical Attack Dataset for SCADA-Based Industrial Control Systems."*

The dataset itself (the final CSV, raw physical/network logs) is archived separately on Zenodo with a permanent DOI - see [Data Availability](#data-availability) below.

---

## Overview

HyGrid-ICS is a hybrid cyber-physical security dataset collected on a real laboratory testbed combining physical process telemetry (via OpenDSS and OpenPLC) and network traffic telemetry (via Zeek IDS). It contains **29 attack classes** (17 physical/Modbus attacks and 12 network attacks) alongside normal operating traffic.

---

## System Architecture

```
[OpenDSS Simulator]            [Raspberry Pi 4B]
  Microgrid physics model  --->  main_sim.py
  (AC power flow, 5-bus,               |
   real-time, 5 Hz)                    v Modbus-TCP (502)
                                [OpenPLC Runtime v3]
                                   (192.168.1.3)
                                        |
                           +------------+------------+
                           v                         v
                  [Node-RED HMI]              [Kali Linux]
                (192.168.1.2:1880)          Attack Scripts
                CSV logging + UI           (192.168.1.4)
                                                  |
                                            [Zeek IDS]
                                       (conn.log, modbus.log)
```

**Hardware:**
- VM1 (Ubuntu): Node-RED HMI - CSV data logging
- VM2 (Ubuntu): OpenDSS + main_sim.py - physical process simulation
- VM3 (Ubuntu): OpenPLC Runtime v3 - Modbus-TCP PLC
- VM4 (Kali): Zeek IDS + attack scripts
- Gateway: 192.168.1.1

---

## Dataset Summary

| Property | Value |
|---|---|
| **Total samples** | 433,568 |
| **Features** | 43 (27 physical + 11 network + 5 meta) |
| **Classes** | 30 (1 Normal + 29 attacks) |
| **Sampling rate** | ~5 Hz (200 ms) |
| **Missing values** | 0 |
| **Recording duration** | ~24 hours |

---

## Attack Classes

### Physical / Modbus attacks (17 classes)

| ID | Name | Description | MITRE ICS |
|---|---|---|---|
| 1 | FDI_Voltage_Injection | False low-voltage register injection | T0855 |
| 2 | Coil_Manipulation_FC05 | Forcing coils open/closed via FC05 | T0831 |
| 3 | Diagnostic_Flood_FC08 | FC08 diagnostic-command flood | T0814 |
| 4 | Illegal_Address_Injection | Reads against out-of-range register addresses | T0836 |
| 5 | Function_Code_Fuzzing | Out-of-range Modbus function codes | T0843 |
| 6 | Load_Shedding_Sabotage | Fake renewable-energy shortage triggers auto load-shedding | T0831 |
| 7 | Generation_Overload | Fake abundant solar + low battery charge drives overcharging | T0831 |
| 8 | Voltage_Instability | Random high-frequency voltage oscillation (hunting) | T0836 |
| 9 | Battery_Drain_Attack | Forced continuous battery discharge | T0831 |
| 10 | Thermal_Sabotage | Fake low transformer temperature, cooling disabled | T0831 |
| 11 | Frequency_Desync | Fixed fake frequency reading masks a real deviation | T0836 |
| 12 | Reactive_Power_Manipulation | Forced capacitor switching + fake low voltage | T0836 |
| 13 | Bus_Overload_FDI | Coordinated false low-voltage injection across 4 buses | T0855 |
| 14 | Ramp_Attack | Slow, stealthy voltage ramp-down over the full attack duration | T0836 |
| 15 | Impossible_State_Injection | Physically impossible load/solar combination | T0821 |
| 16 | False_Alarm_Injection | Rapid alarm toggling (alarm fatigue) | T0832 |
| 17 | Modbus_Reconnaissance | Register-map enumeration via FC03 | T0846 |

### Network attacks (12 classes)

| ID | Name | Description | MITRE ICS |
|---|---|---|---|
| 101 | ICMP_Flood | ICMP echo-request flood | T0814 |
| 102 | UDP_Flood | UDP amplification-style flood | T0814 |
| 103 | TCP_SYN_Flood | TCP SYN flood (half-open connections) | T0814 |
| 104 | TCP_ACK_Flood | TCP ACK flood | T0814 |
| 105 | HTTP_Flood | HTTP flood against the Node-RED HMI | T0814 |
| 106 | Port_Scan | TCP connect scan over ICS and common ports | T0846 |
| 107 | OS_Scan | TTL/TCP-window-based OS fingerprinting | T0846 |
| 108 | Vulnerability_Scan | ICS-specific vulnerability scanning | T0846 |
| 109 | NodeRED_API_Injection | Payload injection against the Node-RED HTTP API | T0855 |
| 110 | Insider_Threat | Authenticated-operator-style data exfiltration | T0852 |
| 111 | APT_Exfiltration | Slow, low-volume data exfiltration | T0882 |
| 112 | Modbus_Abuse | Unusual-but-valid Modbus function-code combinations | T0846 |

---

## Repository Structure

```
HyGrid-ICS/
├── attacks/                  # 17 physical/Modbus attack scripts (Kali-ATK side)
│   ├── config.py             # Shared PLC/register/timing configuration
│   ├── label_manager.py      # Ground-truth label logger
│   └── attack_XX_*.py
├── network_attacks/          # 12 network attack scripts (Kali-ATK side)
│   ├── net_config.py         # Shared network-attack configuration
│   └── attack_net_XX_*.py
├── masterrunner.py           # Runs all 29 attacks sequentially
├── network_attack_runner.py  # Runs only the network attacks
├── run_single_attack.py      # Launches one physical attack interactively
├── LICENSE                   # CC BY 4.0
└── TECHNICAL_NOTES.md         # Known data-quality notes and caveats
```

---

## Usage

```bash
# Run the full 29-attack sequence (test mode, 30s per attack)
python masterrunner.py --attack-time 30

# Full production run (10 minutes per attack), with Zeek started automatically
python masterrunner.py --attack-time 600 --baseline 30 --recovery 30 --zeek --zeek-iface eth0

# Network attacks only
python masterrunner.py --only-network

# Launch a single physical attack interactively
python run_single_attack.py
```

Requires `pymodbus`, and (on the Kali-MON node) a working Zeek installation with its standard/default logging (`conn.log`, `modbus.log`) - no custom policy script is required; the 200 ms feature aggregation is performed afterward by `fusion.py`.

---

## Data Availability

The HyGrid-ICS dataset is publicly available at **https://doi.org/10.5281/zenodo.23250468**. The archive includes:
- The final fused dataset (`scada_cps_dataset.csv`)
- Raw physical telemetry and network logs (`.pcap`, Zeek `conn.log`/`modbus.log`)
- This repository's attack scripts, Zeek policy script, and Node-RED flow export (`.json`)

---

## Ethical Use

This dataset and the accompanying scripts were generated on an isolated laboratory testbed and are intended **for academic research and defensive security purposes only**. Use against real/production systems is strictly prohibited.

---

## License

Released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) - see [LICENSE](LICENSE).

## Citation

If you use this dataset or code, please cite the HyGrid-ICS paper (citation details to be added upon publication).
