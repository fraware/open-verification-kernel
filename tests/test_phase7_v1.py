import json
import subprocess
import sys
from pathlib import Path

from ovk.core.capabilities import CapabilityRegistry
from ovk.core.release_metadata import release_metadata
from ovk.core.templates_cli import list_templates


def test_formal_pr_bench_has_one_hundred_cases() -> None:
    expanded = json.loads(Path("benchmarks/formal_pr_bench/seed_cases_expanded.json").read_text(encoding="utf-8"))
    assert len(expanded["cases"]) == 100


def test_expanded_benchmark_scores_green() -> None:
    result = subprocess.run(
        [sys.executable, "benchmarks/formal_pr_bench/score_all_lanes.py", "--expanded"],
        cwd=Path("."),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_extended_benchmark_categories_present() -> None:
    extended = json.loads(Path("benchmarks/formal_pr_bench/extended_cases.json").read_text(encoding="utf-8"))
    categories = {case["category"] for case in extended["cases"]}
    assert {"routing", "adversarial", "repair_loop", "multi_backend", "intent_recall"}.issubset(categories)


def test_bench_cli_writes_leaderboard(tmp_path: Path) -> None:
    output = tmp_path / "leaderboard.json"
    result = subprocess.run(
        [sys.executable, "-m", "ovk.cli", "bench", "--no-extended", "--leaderboard", str(output)],
        cwd=Path("."),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "formal_pr_bench.leaderboard.v1"
    assert payload["summary"]["cases_passed"] == payload["summary"]["cases_total"]


def test_v1_readiness_checklist() -> None:
    metadata = release_metadata()
    backends = {
        manifest.get("tool", {}).get("name")
        for manifest in CapabilityRegistry.from_directory(Path("adapters")).all()
    }
    required_backends = {"opa", "z3", "cedar", "tla+", "kani", "dafny", "verus", "lean", "cbmc", "alloy"}
    assert required_backends.issubset(backends)
    assert len(list_templates()) >= 100
    assert metadata["version"] == "1.0.0"
    assert "ovk bench" in metadata["supported_commands"]


def test_pilot_program_has_five_manifests() -> None:
    manifests = list(Path("examples/pilot_repos").glob("*.json"))
    assert len(manifests) >= 5
