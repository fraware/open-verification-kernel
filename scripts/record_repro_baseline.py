#!/usr/bin/env python
"""Record a reproducible multi-command baseline for OVK (OVK-01)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.json_io import read_json_file  # noqa: E402
from ovk.core.schema_validation import validate_against_schema  # noqa: E402
from ovk.paths import schema_path  # noqa: E402

SCHEMA_VERSION = "ovk.repro_baseline.v1"
OPTIONAL_CHECKERS = (
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
)

BASELINE_PIP_INSTALL: tuple[str, ...] = (sys.executable, "-m", "pip", "install", "-e", ".[dev]")
BASELINE_PYTEST: tuple[str, ...] = (sys.executable, "-m", "pytest")
BASELINE_REPAIR_LOOP: tuple[str, ...] = (
    sys.executable,
    "examples/repair_loops/ci_secrets/demo_repair_loop.py",
)


def _ovk_command(*args: str) -> tuple[str, ...]:
    """Prefer the installed ``ovk`` console script; fall back to ``python -m ovk.cli``."""
    ovk_bin = shutil.which("ovk")
    if ovk_bin:
        return (ovk_bin, *args)
    return (sys.executable, "-m", "ovk.cli", *args)


def baseline_commands(*, skip_install: bool = False) -> list[tuple[str, ...]]:
    commands: list[tuple[str, ...]] = []
    if not skip_install:
        commands.append(BASELINE_PIP_INSTALL)
    commands.extend(
        [
            BASELINE_PYTEST,
            _ovk_command("doctor"),
            _ovk_command(
                "check",
                "--changed-files",
                "examples/multi_surface/pr_combined.diff",
                "--advisory",
            ),
            _ovk_command("release-preflight"),
            BASELINE_REPAIR_LOOP,
        ]
    )
    return commands


SKIPPED_TEST_RE = re.compile(r"^(SKIPPED|skipped)\s+([^\s].*)$")
PYTEST_SKIP_SUMMARY_RE = re.compile(r"(\d+)\s+skipped")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _probe_network_access(timeout_seconds: float = 2.0) -> bool:
    override = os.environ.get("OVK_NETWORK_ACCESS")
    if override is not None:
        return override.strip().lower() in {"1", "true", "yes", "on"}
    try:
        urllib.request.urlopen("https://pypi.org/simple/", timeout=timeout_seconds)  # noqa: S310
        return True
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _git_sha(repo_root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _ensure_verification_dir(repo_root: Path, logs_dir: Path) -> None:
    verification = repo_root / ".verification"
    if verification.exists():
        return
    argv = list(_ovk_command("init"))
    stdout_path = logs_dir / "setup-ovk-init.stdout.log"
    stderr_path = logs_dir / "setup-ovk-init.stderr.log"
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr:
        subprocess.run(argv, cwd=repo_root, check=False, stdout=stdout, stderr=stderr)


def _parse_skipped_tests(pytest_stdout: str) -> list[str]:
    skipped: list[str] = []
    for line in pytest_stdout.splitlines():
        match = SKIPPED_TEST_RE.match(line.strip())
        if match:
            skipped.append(match.group(2).strip())
    if skipped:
        return sorted(set(skipped))
    # Fallback: capture summary count only when individual lines are unavailable.
    summary = PYTEST_SKIP_SUMMARY_RE.search(pytest_stdout)
    if summary and int(summary.group(1)) > 0:
        return [f"<pytest reported {summary.group(1)} skipped test(s)>"]
    return []


def _checker_availability_from_doctor(doctor_payload: dict[str, Any] | None) -> dict[str, Any]:
    availability: dict[str, Any] = {}
    if not doctor_payload:
        return availability
    checks = doctor_payload.get("checks") or []
    for check in checks:
        if not isinstance(check, dict):
            continue
        name = str(check.get("name") or "")
        if name not in OPTIONAL_CHECKERS:
            continue
        availability[name] = {
            "available": bool(check.get("passed")),
            "message": str(check.get("message") or ""),
        }
    return availability


def _command_slug(argv: tuple[str, ...]) -> str:
    parts = []
    for part in argv:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(part).name if "/" in part or "\\" in part else part)
        parts.append(cleaned.strip("-") or "arg")
    return "-".join(parts)[:120]


def run_command(
    argv: tuple[str, ...],
    *,
    repo_root: Path,
    logs_dir: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    slug = _command_slug(argv)
    stdout_path = logs_dir / f"{slug}.stdout.log"
    stderr_path = logs_dir / f"{slug}.stderr.log"
    started = time.perf_counter()
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr:
        completed = subprocess.run(
            list(argv),
            cwd=repo_root,
            check=False,
            stdout=stdout,
            stderr=stderr,
            env=env,
        )
    elapsed = time.perf_counter() - started
    return {
        "argv": [str(part) for part in argv],
        "exit_code": int(completed.returncode),
        "elapsed_seconds": round(elapsed, 3),
        "stdout_path": str(stdout_path.relative_to(repo_root)).replace("\\", "/"),
        "stderr_path": str(stderr_path.relative_to(repo_root)).replace("\\", "/"),
    }


def collect_artifacts(repo_root: Path, extra_globs: list[str]) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    default_names = (
        "ovk-evidence.json",
        "ovk-pr-comment.md",
        "ovk-evidence-quality.json",
        "ovk-attestation.json",
        "ovk-artifact-manifest.json",
    )
    for name in default_names:
        path = repo_root / name
        if path.is_file():
            candidates.append(path)
    for pattern in extra_globs:
        candidates.extend(p for p in repo_root.glob(pattern) if p.is_file())

    artifacts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(set(candidates), key=lambda item: str(item)):
        rel = str(path.relative_to(repo_root)).replace("\\", "/")
        if rel in seen:
            continue
        seen.add(rel)
        artifacts.append(
            {
                "path": rel,
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    return artifacts


def normalize_os_label(system: str | None = None) -> str:
    name = (system or platform.system()).lower()
    if name.startswith("darwin") or name == "macos":
        return "macos"
    if name.startswith("win"):
        return "windows"
    if name.startswith("linux"):
        return "linux"
    return re.sub(r"[^a-z0-9]+", "-", name).strip("-") or "unknown"


def default_output_path(repo_root: Path) -> Path:
    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    return repo_root / "docs" / "baselines" / f"repro-{normalize_os_label()}-py{py}.json"


def validate_baseline_record(record: dict[str, Any]) -> list[str]:
    schema_file = schema_path("repro.baseline.schema.json")
    if not schema_file.exists():
        # Fall back to repo-relative schema when package data is not synced yet.
        schema_file = ROOT / "schemas" / "repro.baseline.schema.json"
    schema = read_json_file(schema_file)
    report = validate_against_schema(record, schema)
    failures = [
        f"{'/'.join(str(part) for part in issue.path) or '$'}: {issue.message}" for issue in report.issues
    ]
    required = (
        "schema_version",
        "python_version",
        "os",
        "platform",
        "network_access",
        "started_at",
        "completed_at",
        "elapsed_seconds",
        "checker_availability",
        "skipped_tests",
        "commands",
        "artifacts",
    )
    for field in required:
        if field not in record:
            failures.append(f"missing required field {field!r}")
    return failures


def record_baseline(
    *,
    repo_root: Path,
    output: Path,
    skip_install: bool = False,
    artifact_globs: list[str] | None = None,
) -> dict[str, Any]:
    logs_dir = repo_root / ".verification" / "repro-baseline-logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    started_at = _utc_now()
    wall_started = time.perf_counter()
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")

    _ensure_verification_dir(repo_root, logs_dir)

    commands_spec = baseline_commands(skip_install=skip_install)

    command_records: list[dict[str, Any]] = []
    doctor_payload: dict[str, Any] | None = None
    skipped_tests: list[str] = []

    for argv in commands_spec:
        record = run_command(argv, repo_root=repo_root, logs_dir=logs_dir, env=env)
        command_records.append(record)

        stdout_rel = record.get("stdout_path")
        if stdout_rel:
            stdout_text = (repo_root / stdout_rel).read_text(encoding="utf-8", errors="replace")
            if any(part == "pytest" or part.endswith("pytest") for part in argv):
                skipped_tests = _parse_skipped_tests(stdout_text)
            if "doctor" in argv:
                try:
                    doctor_payload = json.loads(stdout_text)
                except json.JSONDecodeError:
                    doctor_payload = None

    artifacts = collect_artifacts(repo_root, artifact_globs or [])
    # Always hash the command logs themselves for provenance.
    for path in sorted(logs_dir.glob("*.log")):
        rel = str(path.relative_to(repo_root)).replace("\\", "/")
        artifacts.append({"path": rel, "sha256": _sha256_file(path), "bytes": path.stat().st_size})

    completed_at = _utc_now()
    elapsed = round(time.perf_counter() - wall_started, 3)
    try:
        from ovk import __version__ as ovk_version
    except Exception:  # noqa: BLE001
        ovk_version = "unknown"

    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "python_version": platform.python_version(),
        "os": normalize_os_label(),
        "platform": platform.platform(),
        "runner": os.environ.get("RUNNER_OS") or platform.system(),
        "network_access": _probe_network_access(),
        "started_at": started_at,
        "completed_at": completed_at,
        "elapsed_seconds": elapsed,
        "ovk_version": ovk_version,
        "git_sha": _git_sha(repo_root),
        "checker_availability": _checker_availability_from_doctor(doctor_payload),
        "skipped_tests": skipped_tests,
        "commands": command_records,
        "artifacts": artifacts,
        "passed": all(item.get("exit_code") == 0 for item in command_records),
        "notes": [
            "Harness may run `ovk init` once when `.verification/` is missing so `ovk doctor` can pass.",
            "Command stdout/stderr captured under .verification/repro-baseline-logs/.",
        ],
    }

    failures = validate_baseline_record(record)
    if failures:
        raise ValueError("baseline schema incomplete:\n" + "\n".join(failures))

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Record an OVK reproducible baseline")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Skip pip install -e '.[dev]' (useful when the environment is already prepared)",
    )
    parser.add_argument(
        "--artifact-glob",
        action="append",
        default=[],
        help="Extra glob (relative to repo root) to include in artifact hashing",
    )
    parser.add_argument(
        "--validate-only",
        type=Path,
        default=None,
        help="Validate an existing baseline JSON and exit",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()

    if args.validate_only is not None:
        payload = read_json_file(args.validate_only.resolve())
        failures = validate_baseline_record(payload)
        if failures:
            for failure in failures:
                print(failure, file=sys.stderr)
            return 1
        print(f"baseline schema valid: {args.validate_only}")
        return 0

    output = (args.output or default_output_path(repo_root)).resolve()
    try:
        record = record_baseline(
            repo_root=repo_root,
            output=output,
            skip_install=args.skip_install,
            artifact_globs=list(args.artifact_glob),
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1

    print(f"wrote baseline -> {output}")
    print(f"passed={record.get('passed')} elapsed_seconds={record.get('elapsed_seconds')}")
    return 0 if record.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
