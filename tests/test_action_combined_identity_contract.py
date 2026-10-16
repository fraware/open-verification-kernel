"""Regression contract for combined Action version and source identity.

These assertions cover the ordering and fail-closed composition of the
independently tested installer and source-binding helper. They do not establish
GitHub event authenticity, source-to-model fidelity, or relying authority.
"""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _steps() -> list[dict]:
    """Load exactly the composite steps delivered to downstream Action users."""
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    return action["runs"]["steps"]


def test_version_identity_precedes_verified_source_binding() -> None:
    """Failure to resolve an explicitly requested version must stop the Action."""
    steps = _steps()
    names = [step.get("name") for step in steps]
    for required in ("Install OVK package", "Initialize verification directory if needed",
                     "Prepare change input", "Run OVK check path"):
        assert names.count(required) == 1

    install_i = names.index("Install OVK package")
    init_i = names.index("Initialize verification directory if needed")
    prepare_i = names.index("Prepare change input")
    check_i = names.index("Run OVK check path")
    assert install_i < init_i < prepare_i < check_i

    install = steps[install_i]
    assert install["shell"] == "bash"
    assert "set -euo pipefail" in install["run"]
    assert 'pip install "open-verification-kernel==${OVK_PACKAGE_VERSION}"' in install["run"]
    assert '|| install_from_checkout' not in install["run"]
    assert "install_from_checkout" in install["run"]

    prepare = steps[prepare_i]
    assert "set -euo pipefail" in prepare["run"]
    assert "scripts/prepare_verified_change_input.py" in prepare["run"]
    assert prepare["env"]["OVK_GITHUB_SHA"] == "${{ github.sha }}"
    assert prepare["env"]["OVK_EVENT_HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert prepare["env"]["OVK_EVENT_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert "--github-sha" in prepare["run"] and "--base-sha" in prepare["run"]
    assert "--pr-head-sha" in prepare["run"]


def test_unbound_manual_diff_cannot_be_published_by_default_check_path() -> None:
    """An advisory caller-selected diff is explicitly outside the bound PR verdict."""
    steps = _steps()
    by_name = {step["name"]: step for step in steps}
    check = by_name["Emit OVK GitHub check (check path)"]
    comment = by_name["Post OVK pull-request comment"]
    assert "inputs.changed-files == ''" in check["if"]
    assert "inputs.changed-files == ''" in comment["if"]
    # Explicit manifests bypass source binding; public comments are forbidden.
    assert "inputs.verification-manifest == ''" in comment["if"]

    upload = by_name["Upload OVK artifacts"]
    assert "ovk-source-binding.json" in upload["with"]["path"]
    # A receipt sidecar exists, but it remains outside the signed envelope.
    source_doc = (ROOT / "docs/PR_SOURCE_BINDING_V1.md").read_text(encoding="utf-8")
    assert "bound_into_signed_evidence_envelope=false" in source_doc
