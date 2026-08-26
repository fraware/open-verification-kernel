"""Regression tests for release SBOM generation and publication wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import generate_sbom


def _write_pyproject(path: Path) -> None:
    path.write_text(
        """[project]
name = "open-verification-kernel"
version = "1.3.0-rc.1"
dependencies = [
  "jsonschema>=4.22.0",
  "typer>=0.12.0",
  "pydantic>=2.7.0",
  "pyyaml>=6.0.0",
]
""",
        encoding="utf-8",
    )


def _valid_sbom() -> dict:
    component_names = ["jsonschema", "typer", "pydantic", "PyYAML"]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": "open-verification-kernel",
                "version": "1.3.0-rc.1",
                "bom-ref": "root",
            }
        },
        "components": [
            {"type": "library", "name": name, "version": "1.0", "bom-ref": f"dep-{index}"}
            for index, name in enumerate(component_names)
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": [f"dep-{index}" for index in range(len(component_names))]}
        ],
    }


def test_project_metadata_extracts_runtime_dependencies(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject)

    name, version, dependencies = generate_sbom._project_metadata(pyproject)

    assert name == "open-verification-kernel"
    assert version == "1.3.0-rc.1"
    assert dependencies == {"jsonschema", "typer", "pydantic", "pyyaml"}


def test_validate_sbom_accepts_release_inventory(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject)

    generate_sbom._validate_sbom(_valid_sbom(), pyproject=pyproject)


def test_validate_sbom_fails_closed_on_missing_direct_dependency(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject)
    payload = _valid_sbom()
    payload["components"] = [
        item for item in payload["components"] if item["name"].lower() != "pydantic"
    ]

    with pytest.raises(ValueError, match="pydantic"):
        generate_sbom._validate_sbom(payload, pyproject=pyproject)


def test_validate_sbom_fails_closed_on_wrong_root_version(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject)
    payload = _valid_sbom()
    payload["metadata"]["component"]["version"] = "0.0.0"

    with pytest.raises(ValueError, match="root component version"):
        generate_sbom._validate_sbom(payload, pyproject=pyproject)


def test_generate_sbom_uses_reproducible_validated_upstream_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject)
    target_python = tmp_path / "venv" / "bin" / "python"
    target_python.parent.mkdir(parents=True)
    target_python.write_text("", encoding="utf-8")
    output = tmp_path / "release" / "sbom.cdx.json"
    observed: list[str] = []

    monkeypatch.setattr(generate_sbom, "_installed_generator_version", lambda: "7.3.1")

    def fake_run(command: list[str], *, check: bool) -> None:
        assert check is True
        observed.extend(command)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(_valid_sbom()), encoding="utf-8")

    monkeypatch.setattr(generate_sbom.subprocess, "run", fake_run)

    payload = generate_sbom.generate_sbom(
        target_python=target_python,
        output=output,
        pyproject=pyproject,
        expected_generator_version="7.3.1",
    )

    assert payload["bomFormat"] == "CycloneDX"
    assert observed[:4] == [generate_sbom.sys.executable, "-m", "cyclonedx_py", "environment"]
    assert str(target_python.resolve()) in observed
    assert "--output-reproducible" in observed
    assert "--validate" in observed
    assert observed[observed.index("--spec-version") + 1] == "1.6"
    assert observed[observed.index("--mc-type") + 1] == "library"


def test_generate_sbom_rejects_unpinned_generator_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject)
    target_python = tmp_path / "python"
    target_python.write_text("", encoding="utf-8")
    monkeypatch.setattr(generate_sbom, "_installed_generator_version", lambda: "7.3.0")

    with pytest.raises(RuntimeError, match="does not match required release pin"):
        generate_sbom.generate_sbom(
            target_python=target_python,
            output=tmp_path / "sbom.json",
            pyproject=pyproject,
            expected_generator_version="7.3.1",
        )


def test_publish_workflow_generates_signs_attests_and_attaches_sbom() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert workflow.count("Generate reproducible release SBOM") == 2
    assert "cyclonedx-bom==7.3.1" in workflow
    assert "--expected-generator-version 7.3.1" in workflow
    assert "attestations: write" in workflow
    assert (
        "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1"
        in workflow
    )
    assert "subject-path: dist/*.whl" in workflow
    assert "sbom-path: release/ovk-release-sbom.cdx.json" in workflow
    assert "--extra release/ovk-release-sbom.cdx.json" in workflow
    assert "gh release upload" in workflow
    assert "release/ovk-release-sbom.cdx.json" in workflow
