"""
HyGrid-ICS Dataset Fusion Pipeline
====================================
Merges physical telemetry (Node-RED/HMI CSV), network telemetry (Zeek
conn.log / modbus.log, standard/default Zeek output - no custom policy
script is required), and ground-truth attack labels (labels_*.csv from
LabelManager) into the final time-aligned dataset.

This script performs the temporal fusion, missing-network-row handling,
and attack labeling described in the paper's Data Fusion and Labeling
Pipeline section (timestamp normalization -> inner/left join on a 200 ms
grid -> forward-fill -> type conversion -> label assignment).
"""

import os
import glob
import pandas as pd
import numpy as np


def parse_zeek_log(filepath):
    """Parses a Zeek .log file (TSV) into a DataFrame."""
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found.")
        return pd.DataFrame()

    print(f"[{os.path.basename(filepath)}] Reading...")

    # Find the column headers
    columns = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith('#fields'):
                columns = line.strip().split('\t')[1:]
                break

    if not columns:
        return pd.DataFrame()

    # Read the data with pandas (skip comment lines)
    df = pd.read_csv(filepath, sep='\t', comment='#', names=columns, low_memory=False)
    df.replace('-', np.nan, inplace=True)
    return df


def process_network_features(conn_df, modbus_df):
    """Aggregates Zeek logs into a 200 ms-windowed network feature time series."""
    print("Converting network data into a time series...")

    if conn_df.empty:
        return pd.DataFrame()

    # Numeric conversions
    conn_df['datetime'] = pd.to_datetime(conn_df['ts'].astype(float), unit='s')

    cols_to_numeric = ['orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'duration']
    for col in cols_to_numeric:
        if col in conn_df.columns:
            conn_df[col] = pd.to_numeric(conn_df[col], errors='coerce').fillna(0)

    # Connection-state indicators (attack signatures)
    conn_df['is_rej'] = conn_df['conn_state'].apply(lambda x: 1 if str(x) in ['REJ', 'RSTO', 'RSTR'] else 0)
    conn_df['is_s0']  = conn_df['conn_state'].apply(lambda x: 1 if str(x) == 'S0' else 0)
    conn_df['is_oth'] = conn_df['conn_state'].apply(lambda x: 1 if str(x) == 'OTH' else 0)

    # Resample/aggregate at 200 ms (5 samples/second)
    net_resampled = conn_df.set_index('datetime').resample('200ms').agg(
        zeek_conn_count=('ts', 'count'),
        zeek_orig_bytes=('orig_bytes', 'sum'),
        zeek_resp_bytes=('resp_bytes', 'sum'),
        zeek_orig_pkts=('orig_pkts', 'sum'),
        zeek_resp_pkts=('resp_pkts', 'sum'),
        zeek_duration_mean=('duration', 'mean'),
        zeek_rej_count=('is_rej', 'sum'),
        zeek_s0_count=('is_s0', 'sum'),
        zeek_oth_count=('is_oth', 'sum')
    ).fillna(0)

    # Add modbus.log features if present
    if not modbus_df.empty:
        modbus_df['datetime'] = pd.to_datetime(modbus_df['ts'].astype(float), unit='s')
        modbus_df['is_exception'] = modbus_df['exception'].apply(lambda x: 0 if pd.isna(x) else 1)

        modbus_resampled = modbus_df.set_index('datetime').resample('200ms').agg(
            zeek_modbus_pkts=('ts', 'count'),
            zeek_modbus_exceptions=('is_exception', 'sum')
        ).fillna(0)

        net_resampled = net_resampled.join(modbus_resampled, how='outer').fillna(0)
    else:
        net_resampled['zeek_modbus_pkts'] = 0
        net_resampled['zeek_modbus_exceptions'] = 0

    return net_resampled


def apply_labels(df, labels_df, label_col_name="Attack_Type"):
    """Labels the dataset by matching row timestamps against attack START/END intervals."""
    if labels_df.empty:
        return df

    # Default to "Normal" if not already labeled
    if label_col_name not in df.columns:
        df[label_col_name] = "Normal"

    # The label file has separate START and END rows per attack_id; merge
    # them into (start, end) intervals.
    attack_intervals = {}
    for _, row in labels_df.iterrows():
        att_id = row['attack_id']
        att_name = row['attack_name']
        phase = row['phase']

        # Original timestamp, ISO format
        ts = pd.to_datetime(row['real_timestamp'])

        if att_name == "Normal":
            continue

        if att_id not in attack_intervals:
            attack_intervals[att_id] = {"name": att_name, "start": None, "end": None}

        if "START" in str(phase).upper():
            attack_intervals[att_id]["start"] = ts
        elif "END" in str(phase).upper():
            attack_intervals[att_id]["end"] = ts

    for att_id, info in attack_intervals.items():
        if info["start"] is not None and info["end"] is not None:
            # Update rows falling within this attack's time window
            mask = (df.index >= info["start"]) & (df.index <= info["end"])

            attack_name = info["name"]
            current_labels = df.loc[mask, label_col_name]
            df.loc[mask, label_col_name] = current_labels.apply(
                lambda x: attack_name if x == "Normal" else (x if attack_name in x else f"{x} + {attack_name}")
            )

    return df


def main():
    import argparse
    parser = argparse.ArgumentParser(description="HyGrid-ICS Dataset Fusion")
    parser.add_argument("--dir", type=str, default=None,
                        help="Input data directory (default: dataset/)")
    parser.add_argument("--output", type=str, default=None,
                        help="Output filename (default: scada_cps_dataset.csv)")
    args = parser.parse_args()

    print("="*60)
    print("HyGrid-ICS DATASET FUSION PIPELINE")
    print("="*60)

    dataset_dir = args.dir or "dataset"
    if not os.path.exists(dataset_dir):
        dataset_dir = "."  # allow running directly inside the dataset directory

    # 1. Load the physical (HMI) telemetry
    hmi_file = os.path.join(dataset_dir, "scada_hmi_data.csv")
    if not os.path.exists(hmi_file):
        print(f"ERROR: {hmi_file} not found!")
        return

    print(f"[HMI] Reading physical telemetry... ({hmi_file})")
    phys_df = pd.read_csv(hmi_file, header=None)

    # Expected column layout for the Node-RED (HMI) CSV output:
    expected_cols = [
        'real_timestamp', 'sim_time',
        'HR0', 'HR1', 'HR2', 'HR3',
        'freq_hz', 'min_voltage', 'total_kw', 'solar_kw',
        'losses_kw', 'latency_ms', 'alarm',
        'v_sub', 'v_ind', 'v_res', 'v_com',
        'T_oil', 'T_hotspot', 'T_ambient', 'cooling_mode',
        'SoC', 'SoH', 'T_battery',
        'irradiance', 'wind_speed', 'prot_bitmask',
        'aging_rate', 'cloud_pct'
    ]

    if len(phys_df.columns) == len(expected_cols):
        phys_df.columns = expected_cols
    else:
        # Fall back to generic column names if the count doesn't match
        phys_df.columns = ['real_timestamp', 'sim_time'] + [f"phys_sensor_{i}" for i in range(1, len(phys_df.columns) - 1)]

    # Parse ISO 8601 timestamps (e.g. 2026-05-18T23:14:46.476) and round to 200 ms
    phys_df['datetime'] = pd.to_datetime(phys_df['real_timestamp']).dt.round('200ms')
    phys_df.set_index('datetime', inplace=True)

    # Average any rows that round to the same 200 ms timestamp
    phys_numeric = phys_df.select_dtypes(include=[np.number])
    phys_df = phys_numeric.groupby('datetime').mean()

    # 2. Load the Zeek logs
    conn_file = os.path.join(dataset_dir, "conn.log")
    modbus_file = os.path.join(dataset_dir, "modbus.log")

    conn_df = parse_zeek_log(conn_file)
    modbus_df = parse_zeek_log(modbus_file)

    net_df = process_network_features(conn_df, modbus_df)

    # 3. Fuse physical and network data on the shared time axis
    print("Fusing physical and network data (time-aligned fusion)...")
    if not net_df.empty:
        # Left-join on the physical time axis; missing network rows become 0
        hybrid_df = phys_df.join(net_df, how='left')

        # NaN in Zeek columns means no traffic was observed in that window
        zeek_cols = [c for c in hybrid_df.columns if c.startswith('zeek_')]
        hybrid_df[zeek_cols] = hybrid_df[zeek_cols].fillna(0)
    else:
        hybrid_df = phys_df.copy()
        print("Warning: no Zeek data found - using physical telemetry only.")

    # 4. Load and apply ground-truth labels
    hybrid_df['Attack_Type'] = "Normal"

    label_files = glob.glob(os.path.join(dataset_dir, "labels_*.csv"))
    print(f"Found {len(label_files)} label file(s).")

    for l_file in label_files:
        print(f"[Label] Processing: {os.path.basename(l_file)}")
        lbl_df = pd.read_csv(l_file)
        hybrid_df = apply_labels(hybrid_df, lbl_df)

    # Add the binary Is_Attack column
    hybrid_df['Is_Attack'] = hybrid_df['Attack_Type'].apply(lambda x: 0 if x == "Normal" else 1)

    # 5. Save the result
    output_name = args.output or "scada_cps_dataset.csv"
    output_file = os.path.join(dataset_dir, output_name)

    # Drop redundant timestamp columns (the datetime index already covers this)
    if 'real_timestamp' in hybrid_df.columns:
        hybrid_df.drop(columns=['real_timestamp'], inplace=True)
    if 'sim_time' in hybrid_df.columns:
        hybrid_df.drop(columns=['sim_time'], inplace=True)

    hybrid_df.to_csv(output_file)
    print("="*60)
    print(" DONE - hybrid dataset generated.")
    print(f" Output        : {output_file}")
    print(f" Total rows    : {len(hybrid_df):,}")
    print(f" Total features: {len(hybrid_df.columns)}")
    print("\n[Class distribution]")
    print(hybrid_df['Attack_Type'].value_counts())
    print("="*60)


if __name__ == "__main__":
    main()
