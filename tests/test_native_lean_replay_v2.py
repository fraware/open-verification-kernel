"""Adapter-contract tests. These are mocks; actual Lean runs in dedicated CI."""

from __future__ import annotations

import hashlib
import stat
import sys
from pathlib import Path

import pytest

from experiments.rtk.native_lean_replay_v2 import replay_proof_term


FIXTURES = (
    Path(__file__).resolve().parents[1]
    / "experiments" / "rtk" / "lean_replay_fixtures_v2"
)


def _mock_checker(tmp_path: Path) -> Path:
    """Simulated command-line checker for adapter plumbing only."""
    path = tmp_path / "fake_lean"
    path.write_text(
        "#!" + sys.executable + "\n"
        "import pathlib,sys\n"
        "if '--version' in sys.argv:\n"
        " print('Lean (version 4.14.0, test, commit synthetic, Release)')\n"
        " sys.exit(0)\n"
        "text=pathlib.Path(sys.argv[1]).read_text()\n"
        "if '0 + n = n' in text and 'Eq.refl n' in text:\n"
        " print('error: type mismatch')\n"
        " sys.exit(1)\n"
        "if 'Eq.refl n' not in text and 'Nat.zero_add n' not in text:\n"
        " print('unknown proof')\n"
        " sys.exit(1)\n"
        "sys.exit(0)\n"
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _check(lean: Path, *, changed: bool, with_fresh: bool = True):
    return replay_proof_term(
        lean=lean,
        source_declaration=FIXTURES / "source_declaration.lean.txt",
        target_declaration=FIXTURES / (
            "target_changed_declaration.lean.txt" if changed
            else "target_unchanged_declaration.lean.txt"
        ),
        historical_proof=FIXTURES / "historical_proof.term.txt",
        fresh_target_proof=(
            FIXTURES / "fresh_target_proof.term.txt"
            if with_fresh and changed else None
        ),
    )


def test_unmodified_term_replays_against_unchanged_target(tmp_path: Path):
    result = _check(_mock_checker(tmp_path), changed=False)
    assert result["source_native_acceptance"] == "ACCEPTED"
    assert result["historical_evidence_applicability"] == "ADMISSIBLE"
    assert result["target_claim_status"] == "UNKNOWN"
    assert result["witness_basis"] == "EXACT_PROOF_TERM_SOURCE_REPLAY"
    assert result["historical_proof_sha256"] == hashlib.sha256(
        (FIXTURES / "historical_proof.term.txt").read_bytes()
    ).hexdigest()


def test_old_term_rejects_changed_true_target_with_new_proof(tmp_path: Path):
    result = _check(_mock_checker(tmp_path), changed=True)
    assert result["source_native_acceptance"] == "ACCEPTED"
    assert result["historical_evidence_applicability"] == "INADMISSIBLE"
    assert result["fresh_target_execution"] == "ACCEPTED"
    assert result["target_claim_status"] == "ESTABLISHED"
    assert result["witness_basis"] == "NATIVE_PROOF_TERM_TYPE_MISMATCH"


def test_missing_checker_is_undetermined(tmp_path: Path):
    result = _check(tmp_path / "missing-lean", changed=True)
    assert result["historical_evidence_applicability"] == "UNDETERMINED"
    assert result["target_claim_status"] == "UNKNOWN"
    assert result["operational_reason"] == "checker_missing_or_wrong_version"


def test_disallow_sorry_even_with_mock_native_success(tmp_path: Path):
    bad = tmp_path / "hole.term"
    bad.write_text("  sorry\n")
    with pytest.raises(ValueError, match="prohibited"):
        replay_proof_term(
            lean=_mock_checker(tmp_path),
            source_declaration=FIXTURES / "source_declaration.lean.txt",
            target_declaration=FIXTURES / "target_changed_declaration.lean.txt",
            historical_proof=bad,
        )


def test_checker_wrong_version_is_undetermined(tmp_path: Path):
    checker = _mock_checker(tmp_path)
    checker.write_text(checker.read_text().replace(
        "Lean (version 4.14.0", "Lean (version 4.99.0"
    ))
    result = _check(checker, changed=True)
    assert result["historical_evidence_applicability"] == "UNDETERMINED"
    assert result["source_native_acceptance"] == "UNKNOWN"
