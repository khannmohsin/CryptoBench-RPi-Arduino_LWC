"""Integration tests: every registered configuration must encrypt and decrypt back to the input.

Needs the C libraries built for this machine (`make build`); configurations whose
library cannot be loaded are skipped.
"""

import os
import subprocess
import sys

import pytest

from lwcbench import registry

pytest.importorskip("psutil", reason="cipher wrappers need psutil (pip install -r requirements.txt)")

# Known bugs in the existing cipher wrappers (decryption does not reproduce the input).
# Non-strict xfail: some depend on memory layout, so they can pass by accident.
#  - CLEFIA: cClefia_main.py passes the key size (128/192/256) as the round count to
#    ClefiaEncrypt/ClefiaDecrypt instead of the value returned by ClefiaKeySet (18/22/26),
#    so the C code reads past the round-key buffer.
#  - Grain-v1, Trivium, Salsa20, Sosemanuk: wrong output even for whole-block input.
KNOWN_ROUND_TRIP_FAILURES = {
    ("clefia", "128", "128"), ("clefia", "128", "192"), ("clefia", "128", "256"),
    ("grain-v1", "-", "80"), ("trivium", "-", "80"),
    ("salsa", "-", "128"), ("sosemanuk", "-", "128"),
}

# Block-cipher wrappers zero-pad the last block on encryption but never strip the padding
# on decryption, so input that is not a whole number of blocks comes back longer.
KNOWN_UNALIGNED_FAILURES = KNOWN_ROUND_TRIP_FAILURES | {
    (c.name, b, k) for c in registry.CIPHERS.values() if c.kind == "block" for b, k in c.configs()}


def all_configs(known_failures):
    for c in registry.CIPHERS.values():
        for block, key in c.configs():
            marks = []
            if (c.name, block, key) in known_failures:
                marks.append(pytest.mark.xfail(reason="known wrapper bug, see comments above"))
            yield pytest.param(c, block, key, marks=marks, id=f"{c.name}-b{block}-k{key}")


# Each configuration runs in its own interpreter, exactly like `benchmark.py all`:
# several wrappers share module names and some C code corrupts memory, so loading
# them all into one process gives crashes and false failures.
CHILD = """
import sys
from lwcbench import registry, runner
from lwcbench.measure import NullCycleCounter, NullEnergyMonitor
name, block, key, src, tmp = sys.argv[1:]
runner.INTERMEDIATE_FILE = tmp + "/imdt/enc.bin"
runner.OUTPUT_DIR = tmp + "/out"
runner.time.sleep = lambda s: None
cipher = registry.get(name)
try:
    runner.load_functions(cipher, key)
except OSError as e:
    print("SKIP:", e); sys.exit(77)
ok = runner.run(cipher, key, block, src, NullCycleCounter(), NullEnergyMonitor(), out_dir=tmp + "/meas")
sys.exit(0 if ok else 1)
"""


def run_child(cipher, block, key, tmp_path, data):
    src = tmp_path / "input.bin"
    src.write_bytes(data)
    return subprocess.run([sys.executable, "-c", CHILD, cipher.name, block, key, str(src), str(tmp_path)],
                          capture_output=True, text=True, timeout=300)


# 4800 bytes is a whole number of blocks for every block size (4, 6, 8, 12, 16 bytes).
ALIGNED = os.urandom(4800)
UNALIGNED = os.urandom(4800) + b"x" * 5


@pytest.mark.parametrize("cipher,block,key", list(all_configs(KNOWN_ROUND_TRIP_FAILURES)))
def test_round_trip_aligned(cipher, block, key, tmp_path):
    check(run_child(cipher, block, key, tmp_path, ALIGNED), cipher, block, key, tmp_path)


@pytest.mark.parametrize("cipher,block,key", list(all_configs(KNOWN_UNALIGNED_FAILURES)))
def test_round_trip_unaligned(cipher, block, key, tmp_path):
    """Input whose length is not a multiple of the block size: padding must be removed on decrypt."""
    check(run_child(cipher, block, key, tmp_path, UNALIGNED), cipher, block, key, tmp_path)


def check(proc, cipher, block, key, tmp_path):
    if proc.returncode == 77:
        pytest.skip("library not loadable on this machine (run `make build`)")
    assert "Traceback" not in proc.stderr, proc.stderr[-2000:]
    assert proc.returncode in (0, 1), f"crashed (exit {proc.returncode}):\n{proc.stderr[-2000:]}"

    row = open(os.path.join(tmp_path, "meas", "encryption_throughput.csv")).read().splitlines()[1].split(",")
    assert row[:3] == [cipher.label, block, key]
    assert proc.returncode == 0, "decrypted output differs from the input"
