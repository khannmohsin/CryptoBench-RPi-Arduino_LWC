"""# Lightweight Cryptographic Cipher Benchmarking Suite

## Overview

This benchmarking suite supports the experimental framework presented in the paper:  
**"Performance Evaluation of Lightweight Cryptographic Ciphers on ARM Processor for IoT Deployments"**  


It enables the performance analysis of multiple lightweight block and stream ciphers implemented in C, using Python as the orchestration layer. The system is optimized for ARM architectures, specifically Raspberry Pi Zero W, and supports comprehensive metric collection including throughput, memory footprint, cycles per byte, and energy consumption.

## Key Features

- Supports **11 lightweight ciphers** (block + stream, hardware- and software-oriented)
- **Customizable framework** allowing easy addition of new ciphers 
- **Real-time CPU cycle tracking** using custom binary
- **Energy measurement integration** via Arduino UNO and INA219 sensor
- Automated execution and logging across cipher variants and key sizes
- Extensible for additional cipher implementations

## Ciphers Supported

### Block Ciphers
- AES
- PRESENT
- XTEA
- CLEFIA
- SIMON
- SPECK

### Stream Ciphers
- Grain-v1
- Grain-128a
- Trivium
- Mickey-v1
- Salsa20
- Sosemanuk

## System Requirements

- **Python 3.8+**
- GCC for C code compilation
- Raspberry Pi Zero W (ARM11 processor)
- Arduino UNO + INA219 power monitor (for energy evaluation)

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Compile C implementations to shared objects:**
   ```bash
   bash run_conversion.sh
   ```

## Usage

### Run All Benchmarks
```bash
bash rb_run_scripts.sh
```

### Run Specific Cipher
```bash
python3 rb_main.py <cipher> <key_size> <input_file> <block_size>
```
Example:
```bash
python3 rb_main.py speck 128 Files/Crypto_input/video/video_2.mp4 64
```

## Folder Structure

- `rb_main.py` – Main orchestration script
- `run_scripts.sh` – Full benchmark execution (C & Python)
- `run_conversion.sh` – Compiles C files into `.so` files
- `LW_Block_Cipher/` – C implementations of lightweight block ciphers
- `LW_Stream_Cipher/` – C implementations of stream ciphers
- `Files/` – Input/output files for testing
- `first_cycles` – Binary for CPU cycle counting
- `output.txt` – Contains measured cycles (temp file)

## Energy Measurement Setup

- INA219 sensor attached between Arduino and Raspberry Pi
- Raspberry Pi communicates cipher start/end to Arduino via GPIO
- Arduino logs real-time power usage during cipher execution

## Academic Reference

If you use this codebase in your work, please cite:
> Khan, M., Johansen, D., & Dagenborg, H. (2025). Performance Evaluation of Lightweight Cryptographic Ciphers on ARM Processor for IoT Deployments. In *SciSec 2024*, LNCS 15441, pp. 254–272. https://doi.org/10.1007/978-981-96-2417-1_14
"""