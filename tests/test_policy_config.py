from pathlib import Path

from ovk.core.compilation_evidence import compilation_failure_evidence
from ovk.core.context import RepositoryContext
from ovk.core.kernel import execute_kernel
from ovk.core.policy_config import bundle_decision_options, resolve_default_on_unknown
from ovk.core.bundle import make_bundle
from ovk.core.decision import decide
from ovk.core.models import MergeRecommendation


def test_resolve_default_on_unknown_falls_back_on_invalid() -> None:
    assert resolve_default_on_unknown({"default_on_unknown": "block"}) == "block"
    assert resolve_default_on_unknown({"default_on_unknown": "not-a-choice"}) == "require_human_review"
    assert resolve_default_on_unknown(None) == "require_human_review"


def test_decide_unknown_blocks_when_configured() -> None:
    evidence = compilation_failure_evidence(
        repo="test/repo",
        head_sha="abc",
        base_sha=None,
        intents=["no-secrets-in-untrusted-context"],
        reason="missing input",
    )
    bundle = make_bundle([evidence], default_on_unknown="block")
    assert bundle.decision["merge_recommendation"] == "block"
    assert decide(bundle, default_on_unknown="block") == MergeRecommendation.BLOCK


def test_kernel_honors_default_on_unknown_block() -> None:
    context = RepositoryContext(
        repo="test/repo",
        head_sha="deadbeef",
        changed_files=["README.md"],
        policy={"default_on_unknown": "block"},
    )
    result = execute_kernel(
        changed_files=["README.md"],
        context=context,
        use_cache=False,
        repo="test/repo",
        head_sha="deadbeef",
    )
    assert result.obligations == []
    assert result.bundle.decision["merge_recommendation"] == "block"


def test_bundle_decision_options_from_policy() -> None:
    assert bundle_decision_options({"default_on_unknown": "allow_with_warning"}) == {
        "default_on_unknown": "allow_with_warning"
    }


def test_load_verification_policy_default_on_unknown(tmp_path: Path, monkeypatch) -> None:
    from ovk.core.context import load_verification_policy

    config_dir = tmp_path / ".verification"
    config_dir.mkdir()
    (config_dir / "config.yml").write_text(
        "schema_version: ovk.config.v1\nmode: strict\ndefault_on_unknown: block\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    policy = load_verification_policy()
    assert policy["default_on_unknown"] == "block"
