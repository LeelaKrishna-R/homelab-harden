import importlib.util
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_pyz.py"


def _build(tmp_path: Path) -> Path:
    spec = importlib.util.spec_from_file_location("build_pyz", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build(tmp_path / "homelab-harden.pyz")


def run(pyz: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(pyz), *args], capture_output=True, text=True)


def test_single_file_build_runs_and_keeps_exit_codes(tmp_path):
    pyz = _build(tmp_path)
    listed = run(pyz, "--list-rules")
    assert listed.returncode == 0 and listed.stdout.startswith("HH001")
    assert run(pyz, "--demo", "--no-color").returncode == 1
    assert run(pyz, "--demo", "--fail-on", "none").returncode == 0
    assert run(pyz, "--ignore", "HH999").returncode == 2
