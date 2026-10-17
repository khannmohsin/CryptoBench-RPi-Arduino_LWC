#!/usr/bin/env python3
"""Benchmark lightweight ciphers: time, throughput, RAM, cycles/byte and energy.

Examples:
    python3 benchmark.py list
    python3 benchmark.py run speck 128 Files/Crypto_input/video/video_2.mp4 64
    python3 benchmark.py run trivium 80 Files/Crypto_input/photo/<file>
    python3 benchmark.py all Files/Crypto_input/video/video_2.mp4 --only aes,speck,simon
    python3 benchmark.py run aes 128 <file> --energy --serial-port /dev/ttyAMA0
"""

import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)  # wrappers load their .so files by repo-relative path
sys.path.insert(0, ROOT)

from lwcbench import registry, runner                     # noqa: E402
from lwcbench.measure import (CycleCounter, EnergyMonitor,  # noqa: E402
                              NullCycleCounter, NullEnergyMonitor)


def cmd_list(_args):
    print(f"{'cipher':<12} {'impl':<7} {'type':<7} {'label':<16} block size -> key sizes")
    for c in registry.CIPHERS.values():
        sizes = "; ".join(f"{b} -> {','.join(k)}" for b, k in c.sizes.items())
        print(f"{c.name:<12} {c.impl:<7} {c.kind:<7} {c.label:<16} {sizes}")


def resolve_block_size(cipher, key_size, block_size):
    """Validate sizes; infer block size when only one fits the key size."""
    if block_size is None:
        candidates = [b for b, keys in cipher.sizes.items() if key_size in keys]
        if len(candidates) != 1:
            sys.exit(f"Please give a block size for {cipher.name} with a {key_size}-bit key "
                     f"(options: {', '.join(candidates) or 'none'}).")
        return candidates[0]
    if block_size not in cipher.sizes or key_size not in cipher.sizes[block_size]:
        options = "; ".join(f"block {b}: keys {','.join(k)}" for b, k in cipher.sizes.items())
        sys.exit(f"{cipher.name} does not support block {block_size} / key {key_size}. Supported: {options}")
    return block_size


def make_cycle_counter(mode):
    if mode == "off":
        return NullCycleCounter()
    if CycleCounter.available():
        return CycleCounter()
    if mode == "on":
        sys.exit("Cycle counting needs ./first_cycles on a Raspberry Pi (ARM Linux).")
    print("Note: ./first_cycles not usable on this machine; skipping cycles-per-byte.")
    return NullCycleCounter()


def make_energy_monitor(args):
    if not args.energy:
        return NullEnergyMonitor()
    try:
        return EnergyMonitor(port=args.serial_port, baudrate=args.baudrate)
    except Exception as e:  # missing pyserial or no device on the port
        sys.exit(f"Could not open the Arduino on {args.serial_port}: {e}")


def cmd_run(args):
    cipher = registry.get(args.cipher)
    if cipher is None:
        sys.exit(f"Unknown cipher '{args.cipher}'. Run `python3 benchmark.py list`.")
    if not os.path.isfile(args.file):
        sys.exit(f"Input file not found: {args.file}")
    block_size = resolve_block_size(cipher, args.key_size, args.block_size)

    ok = runner.run(cipher, args.key_size, block_size, args.file,
                    cycles=make_cycle_counter(args.cycles),
                    energy=make_energy_monitor(args),
                    iterations=args.iterations, out_dir=args.out_dir)
    sys.exit(0 if ok else 1)


def cmd_all(args):
    """Run every configuration, each in a fresh process so RAM figures are not polluted."""
    names = args.only.split(",") if args.only else list(registry.CIPHERS)
    unknown = [n for n in names if n not in registry.CIPHERS]
    if unknown:
        sys.exit(f"Unknown cipher(s): {', '.join(unknown)}")

    failures = []
    for name in names:
        if args.skip_python and registry.CIPHERS[name].impl == "Python":
            continue
        for block_size, key_size in registry.CIPHERS[name].configs():
            cmd = [sys.executable, __file__, "run", name, key_size, args.file, block_size,
                   "--iterations", str(args.iterations), "--out-dir", args.out_dir,
                   "--cycles", args.cycles, "--serial-port", args.serial_port,
                   "--baudrate", str(args.baudrate)]
            if args.energy:
                cmd.append("--energy")
            if subprocess.call(cmd) != 0:
                failures.append(f"{name} block={block_size} key={key_size}")  # crashed or round-trip mismatch
            time.sleep(args.pause)

    print("\nAll runs finished." if not failures else "\nRuns that crashed or failed the round-trip check:\n  " + "\n  ".join(failures))
    sys.exit(1 if failures else 0)


def add_common(p):
    p.add_argument("--iterations", type=int, default=1, help="repetitions per configuration (default 1)")
    p.add_argument("--out-dir", default="Measurements", help="where result CSVs are written")
    p.add_argument("--cycles", choices=["auto", "on", "off"], default="auto",
                   help="cycle counting via ./first_cycles (auto = only on a Raspberry Pi)")
    p.add_argument("--energy", action="store_true",
                   help="signal the Arduino/INA219 energy monitor over serial")
    p.add_argument("--serial-port", default="/dev/ttyAMA0")
    p.add_argument("--baudrate", type=int, default=9600)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show supported ciphers and sizes").set_defaults(func=cmd_list)

    p = sub.add_parser("run", help="benchmark one cipher configuration")
    p.add_argument("cipher")
    p.add_argument("key_size")
    p.add_argument("file")
    p.add_argument("block_size", nargs="?", help="omit for stream ciphers or when it can be inferred")
    add_common(p)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("all", help="benchmark every supported configuration")
    p.add_argument("file")
    p.add_argument("--only", help="comma-separated cipher names (default: all)")
    p.add_argument("--skip-python", action="store_true", help="only run the C implementations")
    p.add_argument("--pause", type=float, default=2.0, help="seconds to wait between runs")
    add_common(p)
    p.set_defaults(func=cmd_all)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    args.func(args)
