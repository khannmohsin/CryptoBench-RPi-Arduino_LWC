"""Generic encrypt/decrypt benchmark loop shared by every cipher."""

import importlib
import os
import secrets
import sys
import time

from . import results
from .registry import Cipher

INTERMEDIATE_FILE = "Files/Crypto_intermediate/encrypted_imdt.enc"
OUTPUT_DIR = "Files/Crypto_output"


def generate_random_key(num_bits, key_format="bytes"):
    key = secrets.token_bytes((num_bits + 7) // 8)
    if key_format == "bits":
        return ''.join(format(b, '08b') for b in key)[:num_bits]
    return key


def _as_bytes(data):
    # Some Python wrappers (e.g. Rabbit) return hex strings rather than bytes.
    return data.encode() if isinstance(data, str) else data


def load_functions(cipher: Cipher, key_size: str):
    """Import the cipher's wrapper module and return (encrypt, decrypt)."""
    if cipher.path not in sys.path:
        sys.path.append(cipher.path)
    module = importlib.import_module(cipher.module)
    enc_name, dec_name = cipher.functions_for(key_size)
    return getattr(module, enc_name), getattr(module, dec_name)


def _measured(fn, data, key, extra, tag, cycles, energy):
    """Run one encrypt/decrypt call while cycle and energy measurement are active."""
    energy.start(tag)
    cycles.start()
    output, elapsed, throughput, ram = fn(data, key, *extra)
    samples = cycles.stop()
    energy.stop()
    return output, elapsed, throughput, ram, samples


def run(cipher: Cipher, key_size: str, block_size: str, file_path: str,
        cycles, energy, iterations=1, out_dir="Measurements"):
    encrypt, decrypt = load_functions(cipher, key_size)
    extra = (int(block_size),) if cipher.pass_block_size else ()

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    size_mb = round(len(plaintext) / (1024 * 1024), 2)
    print("-" * 100)
    print(f"{cipher.label} ({cipher.impl}) | key {key_size} | block {block_size} | "
          f"{file_path} ({size_mb} MB) | {iterations} iteration(s)")
    print("-" * 100)

    # Tag sent to the Arduino; its format must stay in sync with receive_data_from_RP.ino.
    tag = f"{cipher.name}_{block_size}_{key_size}"
    ok = True

    for i in range(iterations):
        print(f"\nIteration {i + 1}/{iterations}")
        key = generate_random_key(int(key_size), cipher.key_format)

        ciphertext, enc_time, enc_tp, enc_ram, enc_samples = _measured(
            encrypt, plaintext, key, extra, tag + "_enc", cycles, energy)
        enc_cpb = cycles.cycles_per_byte(enc_samples, len(plaintext))
        if enc_cpb is not None:
            print(f"Encryption cycles per byte: {enc_cpb} CpB")

        os.makedirs(os.path.dirname(INTERMEDIATE_FILE), exist_ok=True)
        with open(INTERMEDIATE_FILE, 'wb') as f:
            f.write(_as_bytes(ciphertext))

        time.sleep(2)  # let power draw settle between encryption and decryption

        decrypted, dec_time, dec_tp, dec_ram, dec_samples = _measured(
            decrypt, ciphertext, key, extra, tag + "_dec", cycles, energy)
        dec_cpb = cycles.cycles_per_byte(dec_samples, len(plaintext))
        if dec_cpb is not None:
            print(f"Decryption cycles per byte: {dec_cpb} CpB")

        if _as_bytes(decrypted) != plaintext:
            ok = False
            print("WARNING: decrypted output does not match the input file "
                  "(round-trip check failed; metrics were still recorded).")

        results.save_metrics(out_dir, cipher.label, block_size, key_size, {
            "enc_time": enc_time, "dec_time": dec_time,
            "enc_throughput": enc_tp, "dec_throughput": dec_tp,
            "enc_cpb": enc_cpb, "dec_cpb": dec_cpb,
            "enc_ram": enc_ram, "dec_ram": dec_ram,
        })

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        ext = os.path.splitext(file_path)[1]
        with open(os.path.join(OUTPUT_DIR, "decrypted" + ext), 'wb') as f:
            f.write(_as_bytes(decrypted))

    return ok
