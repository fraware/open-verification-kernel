#!/usr/bin/env python
"""Verify RC installability paths: pip wheel + composite Action (OVK-PR9).

Default mode is offline/static: Action SHA pins, Action install steps, and
package metadata. Pass ``--wheel`` to build a wheel and import it from a
directory outside the checkout (requires ``build`` / packaging tools).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.release_metadata import OVK_RELEASE_CANDIDATE  # noqa: E402
from scripts.pin_action_shas import check_paths, DEFAULT_PATHS  # noqa: E402

ACTION_YML = ROOT / "action.yml"


def _check_action_sha_pins() -> list[str]:
    return check_paths(DEFAULT_PATHS)


def _check_action_install_surface() -> list[str]:
    failures: list[str] = []
    if not ACTION_YML.exists():
        return ["missing action.yml"]
    text = ACTION_YML.read_text(encoding="utf-8")
    required_snippets = (
        "uses: actions/cache@",
        "OVK_PACKAGE_VERSION",
        "pip install",
        "sync_package_data.py",
        "using: composite",
    )
    for snippet in required_snippets:
        if snippet not in text:
            failures.append(f"action.yml missing install/trust snippet: {snippet!r}")
    # Require at least one SHA-looking pin after actions/cache@
    if "actions/cache@" in text:
        for line in text.splitlines():
            if "uses: actions/cache@" in line and "@" in line:
                pin = line.split("actions/cache@", 1)[1].split()[0].split("#", 1)[0].strip()
                if len(pin) != 40 or any(c not in "0123456789abcdef" for c in pin.lower()):
                    failures.append(f"actions/cache pin is not a 40-char SHA: {pin!r}")
                break
    return failures


def _check_package_metadata() -> list[str]:
    failures: list[str] = []
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if f'version = "{OVK_RELEASE_CANDIDATE}"' not in pyproject:
        failures.append("pyproject.toml version mismatch for RC install path")
    if 'name = "open-verification-kernel"' not in pyproject:
        failures.append("pyproject.toml missing package name open-verification-kernel")
    if 'ovk = "ovk.cli:app"' not in pyproject:
        failures.append("pyproject.toml missing ovk console script")
    return failures


def _check_wheel_outside_checkout() -> list[str]:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="ovk-rc-wheel-") as tmp:
        tmp_path = Path(tmp)
        dist = tmp_path / "dist"
        dist.mkdir()
        build = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            failures.append(
                "wheel build failed "
                f"(exit {build.returncode}): {(build.stderr or build.stdout)[-500:]}"
            )
            return failures
        wheels = list(dist.glob("*.whl"))
        if not wheels:
            failures.append("wheel build produced no .whl")
            return failures
        target = tmp_path / "site"
        target.mkdir()
        install = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-deps", str(wheels[0]), "-t", str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if install.returncode != 0:
            failures.append(
                "wheel install outside checkout failed: "
                f"{(install.stderr or install.stdout)[-500:]}"
            )
            return failures
        # Import from the isolated target without the repo on sys.path.
        env = os.environ.copy()
        env["PYTHONPATH"] = str(target)
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import ovk; assert ovk.__version__; print(ovk.__version__)",
            ],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if probe.returncode != 0:
            failures.append(
                "outside-checkout import failed: " f"{(probe.stderr or probe.stdout)[-500:]}"
            )
            return failures
        version = (probe.stdout or "").strip()
        if version != OVK_RELEASE_CANDIDATE:
            failures.append(
                f"wheel import version {version!r} != release candidate {OVK_RELEASE_CANDIDATE!r}"
            )
    return failures


def verify_rc_install(*, wheel: bool = False) -> list[str]:
    failures: list[str] = []
    failures.extend(_check_package_metadata())
    failures.extend(_check_action_sha_pins())
    failures.extend(_check_action_install_surface())
    if wheel:
        failures.extend(_check_wheel_outside_checkout())
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheel",
        action="store_true",
        help="Build a wheel and import it from a temp directory outside the checkout",
    )
    parser.add_argument("--json", type=Path, default=None, help="Optional JSON report path")
    args = parser.parse_args()
    failures = verify_rc_install(wheel=args.wheel)
    payload = {
        "schema_version": "ovk.rc_install.v1",
        "package_version": OVK_RELEASE_CANDIDATE,
        "wheel_checked": bool(args.wheel),
        "action_paths": [p.as_posix() for p in DEFAULT_PATHS],
        "passed": not failures,
        "failures": failures,
        "notes": [
            "Composite Action consumers pin an immutable tag/SHA and may set OVK_PACKAGE_VERSION.",
            "Live PyPI availability of this RC remains a maintainer Publish workflow gate.",
        ],
    }
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    for failure in failures:
        print(failure)
    if failures:
        return 1
    mode = "static+wheel" if args.wheel else "static"
    print(f"OVK RC install verification passed ({mode}, {OVK_RELEASE_CANDIDATE})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
