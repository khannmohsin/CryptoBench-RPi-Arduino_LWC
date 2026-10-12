"""Result CSVs: one file per metric, one row per (algorithm, block size, key size).

Repeated runs of the same configuration append another value column to the
existing row, so Measurements/Measurement_main.py can average them.
"""

import csv
import os

HEADER = ['Algorithm', 'Block Size', 'Key Size', 'Value']

METRIC_FILES = {
    "enc_time": "encryption_time.csv",
    "dec_time": "decryption_time.csv",
    "enc_throughput": "encryption_throughput.csv",
    "dec_throughput": "decryption_throughput.csv",
    "enc_cpb": "encryption_CpB.csv",
    "dec_cpb": "decryption_CpB.csv",
    "enc_ram": "encryption_RAM.csv",
    "dec_ram": "decryption_RAM.csv",
}


def update_csv_data(filename, algorithm, block_size, key_size, value):
    rows = []
    if os.path.isfile(filename):
        with open(filename, newline='') as f:
            rows = list(csv.reader(f))[1:]

    for row in rows:
        if row[0] == algorithm and row[1] == str(block_size) and row[2] == str(key_size):
            row.append(value)
            break
    else:
        rows.append([algorithm, block_size, key_size, value])

    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        writer.writerows(rows)


def save_metrics(out_dir, algorithm, block_size, key_size, metrics):
    """Write each metric to its CSV; metrics with value None (e.g. CpB without a counter) are skipped."""
    os.makedirs(out_dir, exist_ok=True)
    for key, filename in METRIC_FILES.items():
        value = metrics.get(key)
        if value is not None:
            update_csv_data(os.path.join(out_dir, filename), algorithm, block_size, key_size, value)
