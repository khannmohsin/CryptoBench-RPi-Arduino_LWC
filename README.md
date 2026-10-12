# CryptoBench-RPi-Arduino_LWC: Lightweight Cryptographic Cipher Benchmarking Suite

## Overview

This benchmarking suite supports the experimental framework presented in the paper:  
**"Performance Evaluation of Lightweight Cryptographic Ciphers on ARM Processor for IoT Deployments"**  


It enables the performance analysis of multiple lightweight block and stream ciphers implemented in C, using Python as the orchestration layer. The system is optimized for ARM architectures, specifically Raspberry Pi Zero W, and supports comprehensive metric collection including throughput, memory footprint, cycles per byte, and energy consumption.

## Key Features

- **18 cipher implementations** (block + stream, C and Python) – run `python3 benchmark.py list`
- **One command-line tool** (`benchmark.py`) with a single cipher registry – adding a cipher is one entry
- **Runs anywhere**: time, throughput and RAM work on any machine; cycles-per-byte and energy switch on automatically / on request when the Raspberry Pi and Arduino are present
- **Round-trip check**: every run verifies that decryption reproduces the input file
- **Real-time CPU cycle tracking** on the Raspberry Pi via the `first_cycles` helper
- **Energy measurement** via Arduino UNO + INA219 sensor

## Ciphers Supported

| Type | C implementation | Python implementation |
|---|---|---|
| Conventional block | AES | AES |
| Lightweight block (SPN) | PRESENT | PRESENT |
| Lightweight block (Feistel) | SIMON, XTEA | SIMON, XTEA |
| Lightweight block (GFN) | CLEFIA | – |
| Lightweight block (ARX) | SPECK | SPECK |
| Stream / lightweight AE | ASCON, Grain-128a, Grain-v1, MICKEY, Trivium, Salsa20, Sosemanuk | – |

Other ciphers in the tree (GIFT, RECTANGLE, PIPO, TWINE, HIGHT, Simeck, CHAM, Lizard, Rabbit) and `LW_Hash_Functions/` are not yet wired into the benchmark.

## System Requirements

- Python 3.8+ and GCC (`make`)
- For cycles per byte: Raspberry Pi (ARM Linux) – the bundled `first_cycles` is a 32-bit ARM binary
- For energy: Arduino UNO + INA219 connected over serial (default `/dev/ttyAMA0`)

## Quick Start

```bash
pip install -r requirements.txt
make build                       # compile every C cipher into a .so
python3 benchmark.py list        # supported ciphers, block sizes and key sizes
python3 benchmark.py run speck 128 Files/Crypto_input/video/video_2.mp4 64
```

All commands must be run from the repository root (or via `benchmark.py`, which changes into it).

## Usage

### Benchmark one configuration
```bash
python3 benchmark.py run <cipher> <key_size> <input_file> [block_size]
```
`block_size` can be omitted for stream ciphers or when only one block size fits the key size.

### Benchmark everything
```bash
python3 benchmark.py all Files/Crypto_input/video/video_2.mp4
python3 benchmark.py all <file> --only aes,present,speck --iterations 5
python3 benchmark.py all <file> --skip-python
```
Each configuration runs in its own process so RAM figures are not affected by earlier runs.

### Options
| Option | Meaning |
|---|---|
| `--iterations N` | repeat each configuration N times (values are appended to the same CSV row) |
| `--out-dir DIR` | where CSVs go (default `Measurements/`) |
| `--cycles auto\|on\|off` | cycle counting with `first_cycles` (`auto` = only on a Raspberry Pi) |
| `--energy` | signal the Arduino to measure energy for each encrypt/decrypt |
| `--serial-port`, `--baudrate` | Arduino serial settings (default `/dev/ttyAMA0`, 9600) |

### Raspberry Pi + Arduino (paper setup)
```bash
python3 benchmark.py all Files/Crypto_input/video/video_2.mp4 --energy --cycles on
```
The original scripts still work: `rb_main.py` (= `benchmark.py run ... --energy --cycles on`), `main.py` (= `--cycles off`), and the `rb_run_scripts*.sh` / `run_scripts*.sh` batch files.

### Output
One CSV per metric in `Measurements/`: `encryption_/decryption_` × `time`, `throughput`, `CpB`, `RAM`.
Rows are `Algorithm, Block Size, Key Size, value1, value2, ...`. `Measurements/Measurement_main.py` aggregates and plots them.

## Adding a Cipher

1. Write a wrapper module next to the implementation exposing
   `encrypt(plaintext, key[, block_size]) -> (ciphertext, time_s, throughput, ram)` and the matching `decrypt`.
2. For C code, add its `.so` to the `LIBS` list in the `Makefile`.
3. Add a `Cipher(...)` entry in [`lwcbench/registry.py`](lwcbench/registry.py).
4. For energy measurements, add its name to `ciphers[]` in `Arduino_code/receive_data_from_RP/receive_data_from_RP.ino`.

## Folder Structure

- `benchmark.py` – command-line entry point
- `lwcbench/` – registry of ciphers (`registry.py`), benchmark loop (`runner.py`), cycle/energy measurement (`measure.py`), CSV output (`results.py`)
- `Makefile` – builds the C ciphers (`run_conversion.sh` calls it)
- `rb_main.py`, `main.py`, `*run_scripts*.sh` – backwards-compatible entry points
- `Conv_cipher/`, `LW_Block_Cipher/`, `LW_Stream_Cipher/` – cipher implementations and Python wrappers
- `Arduino_code/` – Arduino sketch and libraries for the INA219 energy monitor
- `Files/` – input/intermediate/output files
- `Measurements/`, `Results/` – CSV output and results of the paper runs
- `first_cycles` – Raspberry Pi helper binary for CPU cycle counting (writes `output.txt` temporarily)

## Energy Measurement Setup

- INA219 sensor attached between Arduino and Raspberry Pi
- Raspberry Pi sends `<cipher>_<block>_<key>_enc|dec` and `stop` to the Arduino over serial
- Arduino logs real-time power usage during cipher execution

<img src="Manuscript/Dig_circuit.png" alt="Energy Measurement" width="400"/>


[View Energy Measurement Circuit Diagram (PDF)](Manuscript/Schematics_curr_power_measurement.pdf)

## Academic Reference

If you use this codebase in your work, please cite:
> Khan, M., Johansen, D., & Dagenborg, H. (2025). Performance Evaluation of Lightweight Cryptographic Ciphers on ARM Processor for IoT Deployments. In *SciSec 2024*, LNCS 15441, pp. 254–272. https://doi.org/10.1007/978-981-96-2417-1_14
