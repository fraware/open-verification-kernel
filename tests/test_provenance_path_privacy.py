from pathlib import Path

from ovk.core.provenance import material_entry


def test_material_uri_is_workspace_relative(tmp_path: Path) -> None:
    material = tmp_path / "inputs" / "policy.json"
    material.parent.mkdir()
    material.write_text("{}", encoding="utf-8")
    entry = material_entry(material, workspace=tmp_path)
    assert entry["uri"] == "inputs/policy.json"
    assert not entry["uri"].startswith("file:")
    assert str(tmp_path) not in entry["uri"]


def test_external_material_uri_falls_back_to_basename(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    material = tmp_path / "outside.json"
    material.write_text("{}", encoding="utf-8")
    assert material_entry(material, workspace=workspace)["uri"] == "outside.json"
