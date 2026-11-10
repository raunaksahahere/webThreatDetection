"""scripts/sepolia_evidence.py must refuse to run unless it can do so safely. These cases need no network and no keys."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sepolia_evidence.py"


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, cwd=ROOT, timeout=60,
                          env={"PATH": "/usr/bin:/bin", "HOME": str(ROOT / "nonexistent-home")})


def test_missing_deployment_record_stops_with_the_remaining_step(tmp_path):
    p = run("--deployment", str(tmp_path / "none.json"))
    assert p.returncode == 3 and "scripts/testnet.sh deploy" in p.stderr


def test_rehearsal_can_never_write_to_the_committed_evidence_folder(tmp_path):
    dep = tmp_path / "d.json"
    dep.write_text("{}")
    p = run("--deployment", str(dep), "--rehearsal-chain-id", "31337")
    assert p.returncode == 3 and "--out" in p.stderr
    assert not (ROOT / "docs" / "evidence" / "REHEARSAL_EVIDENCE.md").exists()


def test_script_contains_no_key_material_and_never_prints_keys():
    src = SCRIPT.read_text()
    assert "0x59c6995e" not in src and "0xac0974be" not in src  # anvil's public keys belong to the local scripts only
    assert "--private-key" not in src  # keys are used in-process, never placed on a command line
    assert "print(reporter_key" not in src and "print(reviewer_key" not in src
