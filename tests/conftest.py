import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def repo_root_cwd(monkeypatch):
    """Cipher wrappers load their .so files by repo-relative path."""
    monkeypatch.chdir(ROOT)


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Redirect every file the runner writes into tmp_path and skip the 2 s settle pause."""
    from lwcbench import runner
    monkeypatch.setattr(runner, "INTERMEDIATE_FILE", str(tmp_path / "imdt" / "enc.bin"))
    monkeypatch.setattr(runner, "OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    return tmp_path


@pytest.fixture
def sample_file(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(os.urandom(4800))
    return str(path)
