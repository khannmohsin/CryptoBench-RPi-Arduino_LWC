"""Fast tests for the benchmark framework itself (no cipher libraries or hardware needed)."""

import csv
import os
import sys
import types

import pytest

import benchmark
from lwcbench import registry, results, runner
from lwcbench.measure import CycleCounter, NullCycleCounter, NullEnergyMonitor
from lwcbench.registry import STREAM, Cipher


def read_csv(path):
    with open(path, newline='') as f:
        return list(csv.reader(f))


# ---------------------------------------------------------------- registry

def test_registry_names_are_unique_and_match_keys():
    assert all(name == c.name for name, c in registry.CIPHERS.items())


@pytest.mark.parametrize("cipher", registry.CIPHERS.values(), ids=lambda c: c.name)
def test_registry_entry_is_consistent(cipher):
    assert os.path.isfile(os.path.join(cipher.path, cipher.module + ".py"))
    assert cipher.configs(), "cipher has no configurations"
    for block, key in cipher.configs():
        assert key.isdigit()
        enc, dec = cipher.functions_for(key)
        assert enc and dec, f"no functions for key {key}"
    if cipher.kind == "stream":
        assert list(cipher.sizes) == [STREAM] and not cipher.pass_block_size
    else:
        assert all(b.isdigit() for b in cipher.sizes)


def test_registry_names_known_to_arduino_sketch():
    sketch = open("Arduino_code/receive_data_from_RP/receive_data_from_RP.ino").read()
    for name in registry.CIPHERS:
        assert f'"{name}"' in sketch, f"{name} missing from Arduino ciphers[]"


# ---------------------------------------------------------------- keys

@pytest.mark.parametrize("bits", [64, 80, 96, 128, 144, 192, 256])
def test_random_key_bytes(bits):
    key = runner.generate_random_key(bits)
    assert isinstance(key, bytes) and len(key) == (bits + 7) // 8


@pytest.mark.parametrize("bits", [80, 128])
def test_random_key_bits(bits):
    key = runner.generate_random_key(bits, "bits")
    assert len(key) == bits and set(key) <= {"0", "1"}


def test_random_keys_differ():
    assert runner.generate_random_key(128) != runner.generate_random_key(128)


# ---------------------------------------------------------------- results

def test_update_csv_creates_appends_and_adds_rows(tmp_path):
    f = str(tmp_path / "m.csv")
    results.update_csv_data(f, "A", "64", "128", 1.5)
    results.update_csv_data(f, "A", "64", "128", 2.5)
    results.update_csv_data(f, "B", "-", "80", 3)
    assert read_csv(f) == [results.HEADER,
                           ["A", "64", "128", "1.5", "2.5"],
                           ["B", "-", "80", "3"]]


def test_save_metrics_skips_missing_values(tmp_path):
    metrics = {k: 1 for k in results.METRIC_FILES}
    metrics["enc_cpb"] = metrics["dec_cpb"] = None
    results.save_metrics(str(tmp_path / "out"), "A", "64", "128", metrics)
    written = sorted(os.listdir(tmp_path / "out"))
    assert "encryption_CpB.csv" not in written and len(written) == 6


# ---------------------------------------------------------------- measurement

def test_cycles_per_byte_subtracts_baseline():
    counter = CycleCounter.__new__(CycleCounter)  # skip the 10 s calibration
    counter.baseline = 100
    assert counter.cycles_per_byte([300, 500], 100) == 6


def test_cycle_counter_unavailable_off_pi(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    assert not CycleCounter.available()


def test_null_measurements():
    assert NullCycleCounter().stop() == []
    assert NullCycleCounter().cycles_per_byte([], 10) is None
    NullEnergyMonitor().start("x")
    NullEnergyMonitor().stop()


# ---------------------------------------------------------------- runner (fake cipher)

class RecordingEnergy:
    def __init__(self):
        self.events = []

    def start(self, tag):
        self.events.append(tag)

    def stop(self):
        self.events.append("stop")


class FakeCycles:
    def start(self):
        pass

    def stop(self):
        return [1000]

    def cycles_per_byte(self, samples, n):
        return sum(samples) // n


@pytest.fixture
def fake_cipher(monkeypatch):
    """A XOR 'cipher' registered as an importable module; `broken` corrupts decryption."""
    mod = types.ModuleType("fake_cipher_mod")
    calls = []

    def xor(data, key):
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def enc(data, key, *extra):
        calls.append(("enc", key, extra))
        return xor(data, key), 0.1, 10.0, 1024

    def dec(data, key, *extra):
        calls.append(("dec", key, extra))
        out = xor(data, key)
        return (out[:-1] if mod.broken else out), 0.2, 5.0, 2048

    mod.enc, mod.dec, mod.broken, mod.calls = enc, dec, False, calls
    monkeypatch.setitem(sys.modules, "fake_cipher_mod", mod)
    cipher = Cipher("fake", "c-FAKE", ".", "fake_cipher_mod", "enc", "dec",
                    {"64": ["128"]}, pass_block_size=True)
    return cipher, mod


def test_runner_round_trip_records_all_metrics(sandbox, sample_file, fake_cipher):
    cipher, mod = fake_cipher
    energy = RecordingEnergy()
    out = str(sandbox / "meas")
    ok = runner.run(cipher, "128", "64", sample_file, FakeCycles(), energy, iterations=2, out_dir=out)

    assert ok
    assert energy.events == ["fake_64_128_enc", "stop", "fake_64_128_dec", "stop"] * 2
    assert [c[2] for c in mod.calls] == [(64,)] * 4           # block size passed through
    assert mod.calls[0][1] == mod.calls[1][1]                   # same key for enc and dec
    assert mod.calls[0][1] != mod.calls[2][1]                   # fresh key per iteration
    assert len(os.listdir(out)) == 8
    assert read_csv(os.path.join(out, "encryption_time.csv"))[1] == ["c-FAKE", "64", "128", "0.1", "0.1"]
    with open(sample_file, "rb") as f:
        assert open(os.path.join(sandbox, "out", "decrypted.bin"), "rb").read() == f.read()


def test_runner_reports_round_trip_failure(sandbox, sample_file, fake_cipher):
    cipher, mod = fake_cipher
    mod.broken = True
    out = str(sandbox / "meas")
    assert not runner.run(cipher, "128", "64", sample_file, NullCycleCounter(), NullEnergyMonitor(), out_dir=out)
    assert os.path.isfile(os.path.join(out, "encryption_time.csv"))  # metrics still recorded


# ---------------------------------------------------------------- CLI

def test_resolve_block_size_infers_unique_choice():
    assert benchmark.resolve_block_size(registry.get("trivium"), "80", None) == STREAM
    assert benchmark.resolve_block_size(registry.get("speck"), "144", None) == "96"
    assert benchmark.resolve_block_size(registry.get("aes"), "192", "128") == "128"


@pytest.mark.parametrize("cipher,key,block", [
    ("py-speck", "96", None),     # ambiguous: blocks 48, 64, 96
    ("simon", "96", "64"),        # unsupported combination
    ("aes", "80", None),          # unsupported key
])
def test_resolve_block_size_rejects(cipher, key, block):
    with pytest.raises(SystemExit):
        benchmark.resolve_block_size(registry.get(cipher), key, block)


def test_cli_list(capsys):
    args = benchmark.build_parser().parse_args(["list"])
    args.func(args)
    out = capsys.readouterr().out
    assert all(name in out for name in registry.CIPHERS)


@pytest.mark.parametrize("argv,message", [
    (["run", "nope", "128", "x"], "Unknown cipher"),
    (["run", "aes", "128", "missing.file"], "Input file not found"),
    (["all", "x", "--only", "aes,nope"], "Unknown cipher"),
])
def test_cli_errors(argv, message):
    args = benchmark.build_parser().parse_args(argv)
    with pytest.raises(SystemExit) as e:
        args.func(args)
    assert message in str(e.value)


def test_cli_cycles_on_fails_without_pi(monkeypatch):
    monkeypatch.setattr(CycleCounter, "available", staticmethod(lambda *a: False))
    with pytest.raises(SystemExit):
        benchmark.make_cycle_counter("on")
    assert isinstance(benchmark.make_cycle_counter("auto"), NullCycleCounter)


def test_cli_energy_reports_bad_port():
    args = benchmark.build_parser().parse_args(["run", "aes", "128", "f", "--energy",
                                                "--serial-port", "/dev/does-not-exist"])
    with pytest.raises(SystemExit) as e:
        benchmark.make_energy_monitor(args)
    assert "/dev/does-not-exist" in str(e.value)


def test_cli_all_spawns_every_config(monkeypatch, sample_file):
    calls = []
    monkeypatch.setattr(benchmark.subprocess, "call", lambda cmd: calls.append(cmd) or 0)
    args = benchmark.build_parser().parse_args(["all", sample_file, "--only", "speck,trivium",
                                                "--pause", "0", "--energy"])
    with pytest.raises(SystemExit) as e:
        args.func(args)
    assert e.value.code == 0
    assert len(calls) == 6 and all("--energy" in c for c in calls)


def test_cli_all_skip_python(monkeypatch, sample_file):
    calls = []
    monkeypatch.setattr(benchmark.subprocess, "call", lambda cmd: calls.append(cmd) or 0)
    args = benchmark.build_parser().parse_args(["all", sample_file, "--only", "aes,py-aes",
                                                "--pause", "0", "--skip-python"])
    with pytest.raises(SystemExit):
        args.func(args)
    assert {c[3] for c in calls} == {"aes"}


@pytest.mark.parametrize("script,extra", [("rb_main.py", ["--energy", "--cycles", "on"]),
                                          ("main.py", ["--cycles", "off"])])
def test_legacy_entry_points(monkeypatch, script, extra):
    captured = {}
    real = benchmark.build_parser

    def spy():
        parser = real()
        orig = parser.parse_args
        parser.parse_args = lambda argv: captured.setdefault("argv", argv) and orig(argv)
        return parser

    monkeypatch.setattr(benchmark, "build_parser", spy)
    monkeypatch.setattr(sys, "argv", [script, "trivium", "80", "missing.file", "-"])
    import runpy
    with pytest.raises(SystemExit):
        runpy.run_path(script, run_name="__main__")
    assert captured["argv"] == ["run", "trivium", "80", "missing.file", "-", *extra]
