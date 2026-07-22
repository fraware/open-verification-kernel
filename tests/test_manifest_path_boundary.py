import json
from pathlib import Path

import pytest

from ovk.core.multi_lane import manifest_material_paths, run_verification_manifest


def test_manifest_input_cannot_escape_manifest_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    manifest = {"lanes": [{"lane": "infrastructure", "input": "../outside.json"}]}
    with pytest.raises(ValueError, match="escapes manifest root"):
        run_verification_manifest(manifest, root=tmp_path, parallel=False)


def test_manifest_policy_is_recorded_as_provenance_material(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    policy_path = tmp_path / "policy.json"
    input_path.write_text(json.dumps({"resources": []}), encoding="utf-8")
    policy_path.write_text(json.dumps({"blocked_public_sensitivities": ["restricted"]}), encoding="utf-8")
    manifest = {
        "lanes": [
            {
                "lane": "infrastructure",
                "input": "input.json",
                "policy": "policy.json",
            }
        ]
    }
    assert manifest_material_paths(manifest, tmp_path) == [input_path.resolve(), policy_path.resolve()]
