import json
from pathlib import Path

from ovk.core.repo_memory import backend_success_rates, router_historical_priors


def _write_run(path: Path, status: str) -> None:
    path.write_text(
        json.dumps(
            {
                "backend_outcomes": [{"backend": "z3", "status": status}],
                "lanes": ["no-admin-route-bypass"],
                "decision": {"merge_recommendation": "block" if status == "fail" else "require_human_review"},
            }
        ),
        encoding="utf-8",
    )


def test_backend_failure_counts_as_conclusive_execution(tmp_path: Path) -> None:
    _write_run(tmp_path / "run-fail.json", "fail")
    _write_run(tmp_path / "run-unknown.json", "unknown")
    assert backend_success_rates(memory_dir=tmp_path)["z3"] == 0.5


def test_repository_memory_is_disabled_by_default(tmp_path: Path, monkeypatch) -> None:
    _write_run(tmp_path / "run-pass.json", "pass")
    monkeypatch.delenv("OVK_ENABLE_REPOSITORY_MEMORY", raising=False)
    assert router_historical_priors(memory_dir=tmp_path) == {}
    assert router_historical_priors(memory_dir=tmp_path, enabled=True) == {"z3": 1.0}
