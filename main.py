#!/usr/bin/env python3
"""Backwards-compatible entry point used by run_scripts*.sh (no Arduino, no cycle counter).

Equivalent to: python3 benchmark.py run <cipher> <key_size> <file> <block_size> --cycles off
New code should call benchmark.py directly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from benchmark import build_parser  # noqa: E402

if __name__ == "__main__":
    args = build_parser().parse_args(["run", *sys.argv[1:], "--cycles", "off"])
    args.func(args)
