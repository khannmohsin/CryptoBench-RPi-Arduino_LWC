#!/usr/bin/env python3
"""Backwards-compatible entry point used by rb_run_scripts*.sh on the Raspberry Pi.

Equivalent to: python3 benchmark.py run <cipher> <key_size> <file> <block_size> --energy --cycles on
New code should call benchmark.py directly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from benchmark import build_parser  # noqa: E402

if __name__ == "__main__":
    args = build_parser().parse_args(["run", *sys.argv[1:], "--energy", "--cycles", "on"])
    args.func(args)
