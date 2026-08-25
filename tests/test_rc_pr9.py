"""OVK-PR9 TCB document and RC DoD / install verification."""

from __future__ import annotations

from pathlib import Path

from ovk.core.release_metadata import OVK_RELEASE_CANDIDATE
from scripts.render_tcb_doc import render_tcb_body, tcb_doc_stale
from scripts.verify_rc_dod import REMAINING_MAINTAINER_GATES, verify_rc_dod
from scripts.verify_rc_install import verify_rc_install


def test_tcb_doc_present_and_fresh() -> None:
    path = Path("docs/TRUSTED_COMPUTING_BASE.md")
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "Trusted Computing Base" in text
    assert OVK_RELEASE_CANDIDATE in text
    assert "trusted_components" in text
    assert "Composite Action" in text
    assert tcb_doc_stale() == []


def test_tcb_body_lists_advertised_checkers() -> None:
    body = render_tcb_body(Path(".").resolve())
    assert "`opa`" in body
    assert "`lane-authorization`" in body
    assert "GitHub App surface" in body


def test_verify_rc_dod_passes() -> None:
    failures = verify_rc_dod()
    assert failures == [], failures
    assert REMAINING_MAINTAINER_GATES


def test_verify_rc_install_static_passes() -> None:
    failures = verify_rc_install(wheel=False)
    assert failures == [], failures
