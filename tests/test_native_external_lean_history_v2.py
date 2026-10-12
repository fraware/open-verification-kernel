"""External Lean-history adapter tests; no simulated native success claim."""

from __future__ import annotations

from pathlib import Path

import pytest

from experiments.rtk.native_external_lean_history_v2 import (
    _UNSUPPORTED,
    _read_exact,
    _theorem_bytes,
)


NATIVE_SNIPPET = (
    b"inductive X where\n"
    b"  | mk\n\n"
    b"theorem HasType.det (a : Nat) : a = a := by\n"
    b"  rfl\n\n"
    b"/-! Historical explanatory documentation. -/\n"
)


def test_external_history_extracts_verbatim_theorem():
    result = _theorem_bytes(NATIVE_SNIPPET)
    assert result == (
        b"theorem HasType.det (a : Nat) : a = a := by\n"
        b"  rfl"
    )
    assert result in NATIVE_SNIPPET


def test_unrelated_document_change_preserves_historical_proof():
    source = NATIVE_SNIPPET
    target = NATIVE_SNIPPET.replace(b"Historical", b"Revised historical")
    assert source != target
    assert _theorem_bytes(source) == _theorem_bytes(target)


def test_changed_target_theorem_is_detected_before_native_replay():
    source = NATIVE_SNIPPET
    target = source.replace(b"a = a := by", b"a = 0 := by")
    assert _theorem_bytes(source) != _theorem_bytes(target)


@pytest.mark.parametrize(
    "bad",
    [
        b"theorem HasType.det : True := by\n  trivial",
        NATIVE_SNIPPET.replace(
            b"/-! Historical", b"theorem HasType.det : True := by\n  trivial\n\n/-! Historical"
        ),
        NATIVE_SNIPPET.replace(b":= by\n", b":= sorry\n"),
        NATIVE_SNIPPET.replace(
            b"theorem HasType.det", b"theorem DifferentName"
        ),
    ],
)
def test_ambiguous_missing_or_unsupported_theorem_fails_closed(bad):
    with pytest.raises(ValueError):
        _theorem_bytes(bad)


def test_unrelated_local_checkout_fails_immutable_commit_identity(tmp_path: Path):
    (tmp_path / "doc" / "examples").mkdir(parents=True)
    (tmp_path / "doc" / "examples" / "tc.lean").write_bytes(NATIVE_SNIPPET)
    with pytest.raises(ValueError):
        _read_exact(
            tmp_path,
            "410fab7284703f41660ca2454218dcca9b2ec896",
            "c6c3cd21a7ef1e1ae0b5bff7625e941cb93379e9",
        )


@pytest.mark.parametrize(
    "construct",
    [
        "sorry",
        "admit",
        "axiom claim : False",
        "unsafe def dangerous : Nat := 0",
        "import OtherModule",
    ],
)
def test_external_native_case_rejects_unsound_or_untracked_dependencies(construct):
    assert _UNSUPPORTED.search(construct) is not None


def test_external_native_case_allows_named_self_contained_proof():
    assert _UNSUPPORTED.search(NATIVE_SNIPPET.decode("utf-8")) is None
