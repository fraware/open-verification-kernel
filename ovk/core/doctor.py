"""Environment and repository diagnostics for OVK."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ovk import __version__
from ovk.core.json_io import read_json_file
from ovk.core.templates_cli import TEMPLATES_DIR, list_templates


@dataclass(frozen=True)
class DoctorCheck:
    """One diagnostic check result."""

    name: str
    passed: bool
    message: str


def _check_python() -> DoctorCheck:
    version = sys.version_info
    ok = version >= (3, 10)
    return DoctorCheck(
        "python",
        ok,
        f"Python {version.major}.{version.minor}.{version.micro}" + ("" if ok else " (requires >=3.10)"),
    )


def _check_optional_binary(name: str) -> DoctorCheck:
    path = shutil.which(name)
    return DoctorCheck(name, path is not None, path or f"{name} not found in PATH (optional)")


def _check_verification_dir(path: Path) -> DoctorCheck:
    if not path.exists():
        return DoctorCheck("verification_dir", False, f"{path} does not exist; run `ovk init`")
    required = ["intents", "capabilities", "evidence", "config.yml"]
    missing = [item for item in required if not (path / item).exists()]
    if missing:
        return DoctorCheck("verification_dir", False, f"{path} missing: {', '.join(missing)}")
    return DoctorCheck("verification_dir", True, f"{path} layout looks valid")


def _check_templates() -> DoctorCheck:
    templates = list_templates(TEMPLATES_DIR)
    required_templates = 100
    return DoctorCheck(
        "template_library",
        len(templates) >= required_templates,
        f"{len(templates)} intent templates available under {TEMPLATES_DIR}",
    )


def _check_policy_config(path: Path) -> DoctorCheck:
    config_path = path / "config.yml"
    if not config_path.exists():
        return DoctorCheck("verification_config_schema", True, "config.yml not present (optional)")
    schema_path = Path("schemas/verification.config.schema.json")
    if not schema_path.exists():
        return DoctorCheck("verification_config_schema", False, "schemas/verification.config.schema.json missing")
    try:
        import yaml
    except Exception as error:  # noqa: BLE001
        return DoctorCheck("verification_config_schema", False, f"PyYAML unavailable: {error}")
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception as error:  # noqa: BLE001
        return DoctorCheck("verification_config_schema", False, f"invalid YAML: {error}")
    if not isinstance(config, dict):
        return DoctorCheck("verification_config_schema", False, "config.yml must contain a YAML mapping")
    try:
        schema = read_json_file(schema_path)
    except Exception as error:  # noqa: BLE001
        return DoctorCheck("verification_config_schema", False, f"cannot read schema: {error}")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(config), key=lambda item: list(item.path))
    if errors:
        error = errors[0]
        at = "/".join(str(part) for part in error.path) or "$"
        return DoctorCheck("verification_config_schema", False, f"{at}: {error.message}")
    return DoctorCheck("verification_config_schema", True, f"{config_path} is schema-valid")


def _check_schema_index() -> DoctorCheck:
    schema_index = Path("docs/SCHEMA_INDEX.md")
    if not schema_index.exists():
        return DoctorCheck("schema_index", False, "docs/SCHEMA_INDEX.md missing")
    return DoctorCheck("schema_index", True, "schema index present")


def _check_github_token() -> DoctorCheck:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return DoctorCheck("github_token", True, "GitHub token present in environment (Action/CI metadata)")
    return DoctorCheck(
        "github_token",
        True,
        "No GITHUB_TOKEN set (optional locally; required for branch metadata in strict CI)",
    )


def _check_manifest_example() -> DoctorCheck:
    manifest = Path("examples/verification_manifests/full_mvp.json")
    if not manifest.exists():
        return DoctorCheck("example_manifest", False, "full_mvp manifest example missing")
    try:
        data = read_json_file(manifest)
        lanes = data.get("lanes", [])
        return DoctorCheck("example_manifest", isinstance(lanes, list) and len(lanes) >= 5, f"{len(lanes)} lanes in example manifest")
    except Exception as error:  # noqa: BLE001
        return DoctorCheck("example_manifest", False, str(error))


def run_doctor(*, verification_dir: Path = Path(".verification")) -> dict[str, Any]:
    """Run OVK environment diagnostics."""
    optional_binaries = [
        "opa",
        "z3",
        "cedar",
        "tlc",
        "kani",
        "dafny",
        "verus",
        "lean",
        "cbmc",
        "alloy",
        "cosign",
    ]
    checks = [
        DoctorCheck("ovk_version", True, __version__),
        _check_python(),
        *[_check_optional_binary(name) for name in optional_binaries],
        _check_verification_dir(verification_dir),
        _check_policy_config(verification_dir),
        _check_manifest_example(),
        _check_templates(),
        _check_schema_index(),
        _check_github_token(),
        DoctorCheck("platform", True, platform.platform()),
    ]
    failures = [
        check
        for check in checks
        if not check.passed
        and check.name in {
            "python",
            "verification_dir",
            "verification_config_schema",
            "example_manifest",
            "template_library",
            "schema_index",
        }
    ]
    return {
        "passed": len(failures) == 0,
        "checks": [{"name": c.name, "passed": c.passed, "message": c.message} for c in checks],
    }
