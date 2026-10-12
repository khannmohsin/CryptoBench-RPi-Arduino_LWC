"""Hardware-backed measurements: CPU cycles (first_cycles) and energy (Arduino + INA219).

Both are optional so the benchmark also runs on machines without the
Raspberry Pi cycle counter or the Arduino attached.
"""

import os
import platform
import subprocess
import time

CYCLE_BINARY = "./first_cycles"   # writes one cycle sample per line to output.txt
CYCLE_OUTPUT = "output.txt"


class CycleCounter:
    """Samples CPU cycles with the first_cycles helper while an operation runs."""

    def __init__(self, binary=CYCLE_BINARY, calibration_seconds=10):
        self.binary = binary
        self.baseline = 0
        self._proc = None
        self._calibrate(calibration_seconds)

    @staticmethod
    def available(binary=CYCLE_BINARY):
        # first_cycles is a 32-bit ARM Linux binary built for the Raspberry Pi.
        return (os.access(binary, os.X_OK) and platform.system() == "Linux"
                and platform.machine().startswith(("arm", "aarch64")))

    def _calibrate(self, seconds):
        """Average idle cycle count, subtracted from every later sample."""
        print(f"Calibrating idle CPU cycles for {seconds}s ...")
        self.start()
        time.sleep(seconds)
        samples = self.stop()[1:]  # first sample is partial
        self.baseline = int(sum(samples) / len(samples)) if samples else 0

    def start(self):
        self._proc = subprocess.Popen([self.binary])

    def stop(self):
        """Stop sampling and return the raw samples."""
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._proc = None
        if not os.path.exists(CYCLE_OUTPUT):
            return []
        with open(CYCLE_OUTPUT) as f:
            samples = [int(line) for line in f if line.strip()]
        os.remove(CYCLE_OUTPUT)
        return samples

    def cycles_per_byte(self, samples, n_bytes):
        return int(sum(s - self.baseline for s in samples) / n_bytes)


class NullCycleCounter:
    def start(self):
        pass

    def stop(self):
        return []

    def cycles_per_byte(self, samples, n_bytes):
        return None


class EnergyMonitor:
    """Tells the Arduino (receive_data_from_RP.ino) when to start/stop integrating power."""

    def __init__(self, port="/dev/ttyAMA0", baudrate=9600):
        import serial  # pyserial; only needed when energy measurement is enabled
        self.serial = serial.Serial(port=port, baudrate=baudrate, timeout=.1)

    def start(self, tag):
        self.serial.write(tag.encode("utf-8"))

    def stop(self):
        self.serial.write(b"stop")


class NullEnergyMonitor:
    def start(self, tag):
        pass

    def stop(self):
        pass
