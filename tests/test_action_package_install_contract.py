"""Composite Action installation: exact version means no silent source fallback.

Execute the actual Action run block in a sandbox with fake commands. No
package manager or network access is needed, and failed versions cannot be
mistaken for qualified development source installs.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def _action_install_script() -> str:
    data = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    install = [item for item in data["runs"]["steps"] if item.get("name") == "Install OVK package"]
    assert len(install) == 1
    return install[0]["run"]


def _exercise(tmp_path: Path, *, requested_version: str | None, fail_requested: bool = False):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log_path = tmp_path / "commands.log"
    for command in ("pip", "python"):
        program = fake_bin / command
        program.write_text(
            "#!/bin/sh\n"
            f'printf "{command} " >> "$OVK_TEST_LOG"\n'
            'printf "<%s>" "$@" >> "$OVK_TEST_LOG"\n'
            'printf "\\n" >> "$OVK_TEST_LOG"\n'
            'if [ "$OVK_TEST_FAIL_VERSION" = "1" ] && '
            ' [ "$1" = "install" ] && '
            ' [ "$2" = "open-verification-kernel==$OVK_PACKAGE_VERSION" ]; then\n'
            '  exit 47\n'
            'fi\n'
            'exit 0\n',
            encoding="utf-8",
        )
        program.chmod(0o755)
    env = dict(os.environ)
    env.update({
        "PATH": str(fake_bin) + os.pathsep + env.get("PATH", ""),
        "OVK_TEST_LOG": str(log_path),
        "OVK_TEST_FAIL_VERSION": "1" if fail_requested else "0",
    })
    if requested_version is None:
        env.pop("OVK_PACKAGE_VERSION", None)
    else:
        env["OVK_PACKAGE_VERSION"] = requested_version
    result = subprocess.run(
        ["bash", "-c", _action_install_script()],
        cwd=tmp_path,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    return result, log_path.read_text(encoding="utf-8")


def test_requested_version_failed_resolution_does_not_install_from_checkout(tmp_path):
    result, log = _exercise(tmp_path, requested_version="9.9.9", fail_requested=True)
    assert result.returncode == 47
    assert "pip <install><open-verification-kernel==9.9.9>" in log
    assert "sync_package_data.py" not in log
    assert "pip <install><.>" not in log
    assert "OVK installed distribution version" not in result.stdout


def test_requested_version_success_reports_dist_metadata_without_fallback(tmp_path):
    result, log = _exercise(tmp_path, requested_version="1.2.1")
    assert result.returncode == 0, result.stderr
    assert "pip <install><open-verification-kernel==1.2.1>" in log
    assert "python <-c>" in log
    assert "sync_package_data.py" not in log
    assert "pip <install><.>" not in log
    assert "requested distribution version 1.2.1" in result.stdout


def test_unpinned_development_install_is_explicit_source_checkout(tmp_path):
    result, log = _exercise(tmp_path, requested_version=None)
    assert result.returncode == 0, result.stderr
    assert "python <scripts/sync_package_data.py>" in log
    assert "pip <install><.>" in log
    assert "open-verification-kernel==" not in log
    assert "package from Action source checkout" in result.stdout


def test_empty_version_uses_development_checkout(tmp_path):
    result, log = _exercise(tmp_path, requested_version="")
    assert result.returncode == 0, result.stderr
    assert "pip <install><.>" in log


@pytest.mark.parametrize("supplied", ["1.2.1;touch should-not-exist", "1.2.1 $(echo injected)"])
def test_version_is_one_quoted_package_argument(tmp_path, supplied):
    result, log = _exercise(tmp_path, requested_version=supplied)
    assert result.returncode == 0, result.stderr
    assert "pip <install><open-verification-kernel==" + supplied + ">" in log
    assert "sync_package_data.py" not in log
    assert not (tmp_path / "should-not-exist").exists()
