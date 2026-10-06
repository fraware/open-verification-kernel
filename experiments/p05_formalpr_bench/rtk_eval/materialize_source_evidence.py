"""Materialize prior evidence for RTK historical anchors from committed source bytes.

This stage:
- checks out only source revisions,
- discovers candidate evidence from committed files,
- validates candidates with source-revision native validators,
- selects the lexicographically first natively accepted candidate,
- never runs target-revision validators,
- never imports or executes RTK,
- never reads oracle labels.

Freshly generated certificates/results/releases are prohibited as prior evidence.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Iterator


FAMILY_CERTIFYEDGE = "CERTIFYEDGE_PROPERTY_PROFILE"
FAMILY_WORKFLOW = "PCS_WORKFLOW_PROFILE"
FAMILY_VERIFIER = "PCS_VERIFIER_PROFILE_V1"

STATUS_ACCEPTED = "SOURCE_ACCEPTED"
STATUS_NONE = "NO_SOURCE_EVIDENCE"
STATUS_REJECTED = "SOURCE_REJECTED"
STATUS_UNSUPPORTED = "UNSUPPORTED_NATIVE_VALIDATOR"
STATUS_OPERATIONAL = "OPERATIONAL_FAILURE"

PCS_MAIN = "from pcs_core.cli import main; raise SystemExit(main())"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _typed_digest(tag: str, value: Any) -> str:
    return _sha256(tag.encode("utf-8") + b"\x00" + _canonical_bytes(value))


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _artifact(root: Path, path: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha256(path.read_bytes()),
    }


def _artifact_list(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    return sorted(
        (_artifact(root, path) for path in paths if path.is_file()),
        key=lambda row: (row["path"], row["sha256"]),
    )


def _snapshot_digest(artifacts: list[dict[str, str]], policy: dict[str, Any]) -> str:
    return _typed_digest(
        "rtk-evidence-snapshot-v0",
        {"artifacts": artifacts, "completeness_policy": policy},
    )


def _snapshot(
    *,
    repository: str,
    source_sha: str,
    anchor_id: str,
    artifacts: list[dict[str, str]],
    policy: dict[str, Any],
) -> dict[str, Any]:
    digest = _snapshot_digest(artifacts, policy)
    return {
        "snapshot_id": _typed_digest(
            "rtk-evidence-snapshot-id-v0",
            {
                "repository": repository,
                "revision": source_sha,
                "anchor_id": anchor_id,
                "digest": digest,
            },
        ),
        "registry": f"git:{repository}",
        "revision": source_sha,
        "digest": digest,
        "digest_algorithm": "sha256",
        "completeness_policy": policy,
        "artifacts": artifacts,
    }


def _run(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout_sec: int,
) -> dict[str, Any]:
    stdout = b""
    stderr = b""
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_sec,
        )
        stdout = proc.stdout
        stderr = proc.stderr
        return {
            "argv": argv,
            "cwd": cwd.as_posix(),
            "status": "COMPLETED",
            "exit_code": int(proc.returncode),
            "stdout_sha256": _sha256(stdout),
            "stderr_sha256": _sha256(stderr),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        return {
            "argv": argv,
            "cwd": cwd.as_posix(),
            "status": "TIMEOUT",
            "exit_code": None,
            "stdout_sha256": _sha256(stdout),
            "stderr_sha256": _sha256(stderr),
        }
    except OSError as exc:
        stderr = str(exc).encode("utf-8", errors="replace")
        return {
            "argv": argv,
            "cwd": cwd.as_posix(),
            "status": "EXEC_ERROR",
            "exit_code": None,
            "stdout_sha256": _sha256(b""),
            "stderr_sha256": _sha256(stderr),
        }


def _completed_ok(record: dict[str, Any]) -> bool:
    return record["status"] == "COMPLETED" and record["exit_code"] == 0


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git -C {repo} {' '.join(args)} failed ({proc.returncode}): "
            + proc.stderr.decode("utf-8", errors="replace")
        )
    return proc


@contextmanager
def _source_worktree(repo: Path, source_sha: str, root: Path) -> Iterator[Path]:
    worktree = root / source_sha
    if worktree.exists():
        shutil.rmtree(worktree)
    _git(repo, "worktree", "add", "--detach", "--force", str(worktree), source_sha)
    try:
        yield worktree
    finally:
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if worktree.exists():
            shutil.rmtree(worktree, ignore_errors=True)


def _environment() -> dict[str, Any]:
    return {
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }


def _json_candidates(root: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    for path in sorted(root.rglob("*.json")):
        rel_parts = path.relative_to(root).parts
        if ".git" in rel_parts or "target" in rel_parts:
            continue
        value = _load_json(path)
        if value is not None:
            yield path, value


def _candidate_id(prefix: str, root: Path, path: Path) -> str:
    return f"{prefix}:{path.relative_to(root).as_posix()}#{_sha256(path.read_bytes())}"


def _native_verifier_digest(anchor: dict[str, Any]) -> str | None:
    value = (
        anchor.get("context_dimensions", {})
        .get("evaluator", {})
        .get("source")
    )
    return value if isinstance(value, str) and value else None


def _subject_digest(value: str | None) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return _typed_digest("rtk-subject-binding-v0", value)


def _materialize_certifyedge(
    anchor: dict[str, Any],
    worktree: Path,
    *,
    timeout_sec: int,
    cache: dict[str, Any],
) -> dict[str, Any]:
    profile_path = worktree / str(anchor["contract_locator"])
    profile = _load_json(profile_path)
    if profile is None:
        return _base_record(anchor, STATUS_OPERATIONAL, notes=["source profile unreadable"])

    artifact_type = profile.get("output_certificate_artifact")
    if artifact_type != "TraceCertificate.v0":
        return _base_record(
            anchor,
            STATUS_UNSUPPORTED,
            notes=[
                f"holdout-v0 has no frozen CertifyEdge committed-artifact validator for {artifact_type}"
            ],
        )

    build = cache.get("certifyedge_build")
    cargo_target = worktree.parent.parent / "_cargo_target"
    cargo_env = dict(os.environ)
    cargo_env["CARGO_TARGET_DIR"] = str(cargo_target)
    if build is None:
        build = _run(
            ["cargo", "build", "--locked", "--quiet", "-p", "certifyedge"],
            cwd=worktree,
            env=cargo_env,
            timeout_sec=timeout_sec,
        )
        cache["certifyedge_build"] = build
    if not _completed_ok(build):
        return _base_record(
            anchor,
            STATUS_OPERATIONAL,
            notes=["source certifyedge build failed or timed out"],
            candidates=[],
            environment_extra={
                "certifyedge_build": build,
                "cargo_target_dir": str(cargo_target),
            },
        )

    binary = cargo_target / "debug" / ("certifyedge.exe" if os.name == "nt" else "certifyedge")
    if not binary.is_file():
        return _base_record(
            anchor,
            STATUS_OPERATIONAL,
            notes=["source certifyedge binary missing after successful build"],
        )

    property_id = profile.get("property_id")
    success_status = profile.get("valid_success_status")
    formalization = profile.get("formalization")
    required_fields = (
        set(formalization.get("required_fields", []))
        if isinstance(formalization, dict)
        else set()
    )
    required_fields.add("status")
    required_fields.add("property_id")

    candidates: list[dict[str, Any]] = []
    for path, value in _json_candidates(worktree):
        if value.get("property_id") != property_id:
            continue
        if not required_fields.issubset(value):
            continue
        candidate_id = _candidate_id("certifyedge", worktree, path)
        command = _run(
            [str(binary), "--release-mode", "verify-certificate", str(path)],
            cwd=worktree,
            timeout_sec=timeout_sec,
        )
        accepted = (
            _completed_ok(command)
            and value.get("property_id") == property_id
            and value.get("status") == success_status
        )
        candidates.append(
            {
                "candidate_id": candidate_id,
                "locator": path.relative_to(worktree).as_posix(),
                "artifacts": [_artifact(worktree, path)],
                "native_commands": [command],
                "native_accept": bool(accepted),
                "subject_binding": _subject_digest(value.get("trace_hash")),
                "rejection_reason": None if accepted else "source native verification/status rule failed",
            }
        )

    return _finish_record(
        anchor,
        candidates,
        policy={
            "policy_id": "certifyedge-committed-trace-certificate-v0",
            "family": FAMILY_CERTIFYEDGE,
            "source_bytes_only": True,
            "artifact_type": "TraceCertificate.v0",
            "selection": "lexicographically_first_native_accept",
        },
        environment_extra={
            "certifyedge_build": build,
            "cargo_target_dir": str(cargo_target),
        },
    )


def _pcs_runtime(
    worktree: Path,
    *,
    timeout_sec: int,
    cache: dict[str, Any],
) -> dict[str, Any]:
    cached = cache.get("pcs_runtime")
    if isinstance(cached, dict):
        return cached

    pyproject_path = worktree / "python" / "pyproject.toml"
    lock_path = worktree / "python" / "requirements.lock"
    if not pyproject_path.is_file() or not lock_path.is_file():
        result = {
            "ok": False,
            "reason": "source revision lacks python/pyproject.toml or python/requirements.lock",
            "python_executable": None,
            "requirements_lock_sha256": (
                _sha256(lock_path.read_bytes()) if lock_path.is_file() else None
            ),
            "pyproject_sha256": (
                _sha256(pyproject_path.read_bytes()) if pyproject_path.is_file() else None
            ),
            "runtime_setup": [],
        }
        cache["pcs_runtime"] = result
        return result

    try:
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        dependencies = pyproject["project"]["dependencies"]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError):
        result = {
            "ok": False,
            "reason": "source python/pyproject.toml runtime dependencies are unreadable",
            "python_executable": None,
            "requirements_lock_sha256": _sha256(lock_path.read_bytes()),
            "pyproject_sha256": _sha256(pyproject_path.read_bytes()),
            "runtime_setup": [],
        }
        cache["pcs_runtime"] = result
        return result

    if not isinstance(dependencies, list) or not all(
        isinstance(item, str) and item.strip() for item in dependencies
    ):
        result = {
            "ok": False,
            "reason": "source python/pyproject.toml has invalid project.dependencies",
            "python_executable": None,
            "requirements_lock_sha256": _sha256(lock_path.read_bytes()),
            "pyproject_sha256": _sha256(pyproject_path.read_bytes()),
            "runtime_setup": [],
        }
        cache["pcs_runtime"] = result
        return result

    requirements_lock_sha256 = _sha256(lock_path.read_bytes())
    pyproject_sha256 = _sha256(pyproject_path.read_bytes())
    runtime_identity = _typed_digest(
        "rtk-pcs-source-runtime-v1",
        {
            "requirements_lock_sha256": requirements_lock_sha256,
            "pyproject_sha256": pyproject_sha256,
            "host_python": platform.python_version(),
        },
    )
    runtime_root = worktree.parent.parent / "_pcs_runtimes"
    venv_dir = runtime_root / runtime_identity
    ready_marker = venv_dir / ".rtk_runtime_ready"
    python_name = "python.exe" if os.name == "nt" else "python"
    python_executable = (
        venv_dir / "Scripts" / python_name
        if os.name == "nt"
        else venv_dir / "bin" / python_name
    )

    setup_records: list[dict[str, Any]] = []
    reused = (
        python_executable.is_file()
        and ready_marker.is_file()
        and ready_marker.read_text(encoding="utf-8").strip() == runtime_identity
    )

    if not reused:
        if venv_dir.exists():
            shutil.rmtree(venv_dir, ignore_errors=True)
        runtime_root.mkdir(parents=True, exist_ok=True)
        create = _run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            cwd=worktree,
            timeout_sec=timeout_sec,
        )
        setup_records.append(create)
        if not _completed_ok(create) or not python_executable.is_file():
            result = {
                "ok": False,
                "reason": "source-specific virtual environment creation failed",
                "python_executable": None,
                "requirements_lock_sha256": requirements_lock_sha256,
                "pyproject_sha256": pyproject_sha256,
                "runtime_setup": setup_records,
                "runtime_identity": runtime_identity,
                "runtime_reused": False,
            }
            cache["pcs_runtime"] = result
            return result

        install = _run(
            [
                str(python_executable),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "-c",
                str(lock_path),
                *dependencies,
            ],
            cwd=worktree / "python",
            timeout_sec=timeout_sec,
        )
        setup_records.append(install)
        if not _completed_ok(install):
            result = {
                "ok": False,
                "reason": "source-specific locked dependency installation failed",
                "python_executable": str(python_executable),
                "requirements_lock_sha256": requirements_lock_sha256,
                "pyproject_sha256": pyproject_sha256,
                "runtime_setup": setup_records,
                "runtime_identity": runtime_identity,
                "runtime_reused": False,
            }
            cache["pcs_runtime"] = result
            return result

    smoke = _run(
        [
            str(python_executable),
            "-c",
            "from pcs_core.cli import main; print('source-runtime-ok')",
        ],
        cwd=worktree / "python",
        timeout_sec=timeout_sec,
    )
    setup_records.append(smoke)
    if _completed_ok(smoke) and not reused:
        ready_marker.write_text(runtime_identity + "\n", encoding="utf-8")

    result = {
        "ok": _completed_ok(smoke),
        "reason": None if _completed_ok(smoke) else "source-specific runtime import smoke failed",
        "python_executable": str(python_executable),
        "requirements_lock_sha256": requirements_lock_sha256,
        "pyproject_sha256": pyproject_sha256,
        "runtime_setup": setup_records,
        "runtime_identity": runtime_identity,
        "runtime_reused": reused,
    }
    cache["pcs_runtime"] = result
    return result


def _pcs_env(worktree: Path, python_executable: str) -> dict[str, str]:
    env = dict(os.environ)
    source = str(worktree / "python")
    old = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source if not old else source + os.pathsep + old
    env["VIRTUAL_ENV"] = str(Path(python_executable).parent.parent)
    return env


def _pcs_argv(python_executable: str, *args: str) -> list[str]:
    return [python_executable, "-c", PCS_MAIN, *args]


def _release_profile_paths(worktree: Path) -> Iterator[Path]:
    examples = worktree / "examples"
    if not examples.is_dir():
        return
    for path in sorted(examples.rglob("workflow_profile.v0.json")):
        if path.is_file():
            yield path


def _release_manifest(directory: Path) -> dict[str, Any] | None:
    for name in ("release_manifest.v0.json", "ReleaseManifest.v0.json"):
        value = _load_json(directory / name)
        if value is not None:
            return value
    return None


def _release_subject(manifest: dict[str, Any] | None) -> str | None:
    if not isinstance(manifest, dict):
        return None
    chain = manifest.get("chain_root")
    if isinstance(chain, dict):
        trace_hash = chain.get("trace_hash")
        if isinstance(trace_hash, str) and trace_hash:
            return _subject_digest(trace_hash)
    release_id = manifest.get("release_id")
    return _subject_digest(release_id if isinstance(release_id, str) else None)


def _directory_artifacts(root: Path, directory: Path) -> list[dict[str, str]]:
    paths = [
        path for path in sorted(directory.rglob("*"))
        if path.is_file() and ".git" not in path.relative_to(root).parts
    ]
    return _artifact_list(root, paths)


def _materialize_workflow(
    anchor: dict[str, Any],
    worktree: Path,
    *,
    timeout_sec: int,
    cache: dict[str, Any],
) -> dict[str, Any]:
    profile = _load_json(worktree / str(anchor["contract_locator"]))
    if profile is None:
        return _base_record(anchor, STATUS_OPERATIONAL, notes=["source workflow profile unreadable"])
    workflow_id = profile.get("workflow_id")
    runtime = _pcs_runtime(worktree, timeout_sec=timeout_sec, cache=cache)
    runtime_environment = {"source_runtime": runtime}
    if not runtime["ok"] or not isinstance(runtime.get("python_executable"), str):
        return _base_record(
            anchor,
            STATUS_OPERATIONAL,
            notes=[str(runtime.get("reason") or "source-specific pcs runtime unavailable")],
            environment_extra=runtime_environment,
        )
    python_executable = str(runtime["python_executable"])
    env = _pcs_env(worktree, python_executable)

    candidates: list[dict[str, Any]] = []
    for profile_path in _release_profile_paths(worktree):
        embedded = _load_json(profile_path)
        if embedded is None or embedded.get("workflow_id") != workflow_id:
            continue
        directory = profile_path.parent
        artifacts = _directory_artifacts(worktree, directory)
        candidate_id = (
            f"pcs-release:{directory.relative_to(worktree).as_posix()}#"
            f"{_typed_digest('rtk-release-directory-v0', artifacts)}"
        )
        command = _run(
            _pcs_argv(python_executable, "validate-release-chain", str(directory)),
            cwd=worktree / "python",
            env=env,
            timeout_sec=timeout_sec,
        )
        accepted = _completed_ok(command)
        candidates.append(
            {
                "candidate_id": candidate_id,
                "locator": directory.relative_to(worktree).as_posix(),
                "artifacts": artifacts,
                "native_commands": [command],
                "native_accept": bool(accepted),
                "subject_binding": _release_subject(_release_manifest(directory)),
                "rejection_reason": None if accepted else "pcs validate-release-chain failed",
            }
        )

    return _finish_record(
        anchor,
        candidates,
        policy={
            "policy_id": "pcs-committed-release-chain-v0",
            "family": FAMILY_WORKFLOW,
            "source_bytes_only": True,
            "workflow_id": workflow_id,
            "selection": "lexicographically_first_native_accept",
        },
        environment_extra=runtime_environment,
    )


def _iter_verification_results(worktree: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    examples = worktree / "examples"
    if not examples.is_dir():
        return
    for path in sorted(examples.rglob("*.json")):
        value = _load_json(path)
        if value is not None and value.get("artifact_type") == "VerificationResult.v1":
            yield path, value


def _profile_digest(profile: dict[str, Any]) -> str | None:
    integrity = profile.get("integrity")
    if not isinstance(integrity, dict):
        return None
    value = integrity.get("artifact_digest")
    return value if isinstance(value, str) and value else None


def _result_subject(result: dict[str, Any]) -> str | None:
    for key in (
        "trajectory_digest",
        "input_bundle_digest",
        "initial_state_digest",
        "terminal_state_digest",
    ):
        value = result.get(key)
        if isinstance(value, str) and value:
            return _subject_digest(value)
    return None


def _materialize_verifier(
    anchor: dict[str, Any],
    worktree: Path,
    *,
    timeout_sec: int,
    cache: dict[str, Any],
) -> dict[str, Any]:
    profile_path = worktree / str(anchor["contract_locator"])
    profile = _load_json(profile_path)
    if profile is None:
        return _base_record(anchor, STATUS_OPERATIONAL, notes=["source verifier profile unreadable"])

    profile_id = profile.get("verifier_profile_id")
    expected_digest = _profile_digest(profile)
    native_claim = str(anchor["claim_id"]).removeprefix("pcs-verifier-claim:")
    runtime = _pcs_runtime(worktree, timeout_sec=timeout_sec, cache=cache)
    runtime_environment = {"source_runtime": runtime}
    if not runtime["ok"] or not isinstance(runtime.get("python_executable"), str):
        return _base_record(
            anchor,
            STATUS_OPERATIONAL,
            notes=[str(runtime.get("reason") or "source-specific pcs runtime unavailable")],
            environment_extra=runtime_environment,
        )
    python_executable = str(runtime["python_executable"])
    env = _pcs_env(worktree, python_executable)

    cache_key = f"verifier-profile:{anchor['contract_locator']}"
    profile_command = cache.get(cache_key)
    if profile_command is None:
        profile_command = _run(
            _pcs_argv(python_executable, "verifier", "profile", str(profile_path), "--json"),
            cwd=worktree / "python",
            env=env,
            timeout_sec=timeout_sec,
        )
        cache[cache_key] = profile_command
    if not _completed_ok(profile_command):
        return _base_record(
            anchor,
            STATUS_REJECTED if profile_command["status"] == "COMPLETED" else STATUS_OPERATIONAL,
            notes=["source VerifierProfile.v1 failed native validation"],
            environment_extra=runtime_environment,
        )

    candidates: list[dict[str, Any]] = []
    for path, result in _iter_verification_results(worktree):
        verifier_profile = result.get("verifier_profile")
        if not isinstance(verifier_profile, dict):
            continue
        if verifier_profile.get("verifier_profile_id") != profile_id:
            continue
        claim_ids = result.get("claim_ids")
        if not isinstance(claim_ids, list) or native_claim not in claim_ids:
            continue
        candidate_id = _candidate_id("pcs-verification-result", worktree, path)
        command = _run(
            _pcs_argv(python_executable, "verifier", "result", str(path), "--json"),
            cwd=worktree / "python",
            env=env,
            timeout_sec=timeout_sec,
        )
        accepted = (
            _completed_ok(command)
            and result.get("execution_status") == "completed"
            and result.get("decision") == "accept"
            and verifier_profile.get("profile_digest") == expected_digest
        )
        artifacts = _artifact_list(worktree, [profile_path, path])
        candidates.append(
            {
                "candidate_id": candidate_id,
                "locator": path.relative_to(worktree).as_posix(),
                "artifacts": artifacts,
                "native_commands": [profile_command, command],
                "native_accept": bool(accepted),
                "subject_binding": _result_subject(result),
                "rejection_reason": None if accepted else "VerifierProfile/VerificationResult acceptance rule failed",
            }
        )

    return _finish_record(
        anchor,
        candidates,
        policy={
            "policy_id": "pcs-committed-verification-result-v1",
            "family": FAMILY_VERIFIER,
            "source_bytes_only": True,
            "verifier_profile_id": profile_id,
            "claim_id": native_claim,
            "selection": "lexicographically_first_native_accept",
        },
        environment_extra=runtime_environment,
    )


def _base_record(
    anchor: dict[str, Any],
    status: str,
    *,
    notes: list[str] | None = None,
    candidates: list[dict[str, Any]] | None = None,
    environment_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    environment = _environment()
    if environment_extra:
        environment.update(environment_extra)
    return {
        "anchor_id": anchor["anchor_id"],
        "transition_id": anchor["transition_id"],
        "repository": anchor["repository"],
        "source_sha": anchor["source_sha"],
        "family": anchor["family"],
        "claim_id": anchor["claim_id"],
        "contract_locator": anchor["contract_locator"],
        "materialization_status": status,
        "subject_binding": None,
        "selected_candidate_id": None,
        "native_verifier_digest": _native_verifier_digest(anchor),
        "evidence_snapshot": None,
        "candidates": candidates or [],
        "environment": environment,
        "target_native_validator_executed": False,
        "rtk_executed": False,
        "oracle_labels_consulted": False,
        "notes": notes or [],
    }


def _finish_record(
    anchor: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    policy: dict[str, Any],
    environment_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    candidates = sorted(candidates, key=lambda row: row["candidate_id"])
    accepted = [row for row in candidates if row["native_accept"]]
    if not candidates:
        return _base_record(
            anchor, STATUS_NONE, candidates=[], environment_extra=environment_extra
        )
    if not accepted:
        status = (
            STATUS_OPERATIONAL
            if any(
                command["status"] != "COMPLETED"
                for candidate in candidates
                for command in candidate["native_commands"]
            )
            else STATUS_REJECTED
        )
        return _base_record(
            anchor, status, candidates=candidates, environment_extra=environment_extra
        )

    selected = accepted[0]
    snapshot = _snapshot(
        repository=str(anchor["repository"]),
        source_sha=str(anchor["source_sha"]),
        anchor_id=str(anchor["anchor_id"]),
        artifacts=list(selected["artifacts"]),
        policy=policy,
    )
    record = _base_record(
        anchor, STATUS_ACCEPTED, candidates=candidates, environment_extra=environment_extra
    )
    record["selected_candidate_id"] = selected["candidate_id"]
    record["subject_binding"] = selected["subject_binding"]
    record["evidence_snapshot"] = snapshot
    if record["subject_binding"] is None:
        record["materialization_status"] = STATUS_REJECTED
        record["selected_candidate_id"] = None
        record["evidence_snapshot"] = None
        record["notes"].append("natively accepted candidate lacked frozen subject binding")
    return record


def _load_anchors(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("anchor JSONL row must be an object")
            rows.append(value)
    return rows


def _parse_repo(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("--repo must use repository=local_path")
    name, raw = value.split("=", 1)
    return name.strip(), Path(raw).resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--anchors", type=Path, required=True)
    parser.add_argument("--repo", action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, default=None)
    parser.add_argument("--timeout-sec", type=int, default=1800)
    args = parser.parse_args()

    if args.timeout_sec <= 0:
        raise SystemExit("--timeout-sec must be positive")

    repos = dict(_parse_repo(value) for value in args.repo)
    anchors = _load_anchors(args.anchors)
    anchors.sort(
        key=lambda row: (
            str(row["repository"]),
            str(row["source_sha"]),
            str(row["anchor_id"]),
        )
    )

    temp_owner = None
    if args.work_root is None:
        temp_owner = tempfile.TemporaryDirectory(prefix="rtk-source-evidence-")
        work_root = Path(temp_owner.name)
    else:
        work_root = args.work_root.resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    try:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for anchor in anchors:
            key = (str(anchor["repository"]), str(anchor["source_sha"]))
            grouped.setdefault(key, []).append(anchor)

        for (repository, source_sha), members in sorted(grouped.items()):
            repo = repos.get(repository)
            if repo is None:
                raise SystemExit(f"missing --repo checkout for {repository}")
            group_root = work_root / _typed_digest(
                "rtk-source-worktree-v0", {"repository": repository, "source_sha": source_sha}
            )
            group_root.mkdir(parents=True, exist_ok=True)
            with _source_worktree(repo, source_sha, group_root) as worktree:
                cache: dict[str, Any] = {}
                for anchor in sorted(members, key=lambda row: str(row["anchor_id"])):
                    family = anchor["family"]
                    if family == FAMILY_CERTIFYEDGE:
                        record = _materialize_certifyedge(
                            anchor, worktree, timeout_sec=args.timeout_sec, cache=cache
                        )
                    elif family == FAMILY_WORKFLOW:
                        record = _materialize_workflow(
                            anchor, worktree, timeout_sec=args.timeout_sec, cache=cache
                        )
                    elif family == FAMILY_VERIFIER:
                        record = _materialize_verifier(
                            anchor, worktree, timeout_sec=args.timeout_sec, cache=cache
                        )
                    else:
                        record = _base_record(
                            anchor,
                            STATUS_UNSUPPORTED,
                            notes=[f"unsupported anchor family {family}"],
                        )
                    results.append(record)
    finally:
        if temp_owner is not None:
            temp_owner.cleanup()

    results.sort(key=lambda row: str(row["anchor_id"]))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as handle:
        for row in results:
            handle.write(_canonical_bytes(row).decode("utf-8") + "\n")

    payload = args.out.read_bytes()
    counts: dict[str, int] = {}
    for row in results:
        status = str(row["materialization_status"])
        counts[status] = counts.get(status, 0) + 1

    manifest = {
        "schema_version": "rtk.source_evidence_materialization_manifest.v0",
        "record_count": len(results),
        "status_counts": dict(sorted(counts.items())),
        "records_sha256": _sha256(payload),
        "source_native_validators_executed": True,
        "target_native_validators_executed": False,
        "rtk_executed": False,
        "oracle_labels_consulted": False,
        "fresh_evidence_generated": False,
        "selection": "lexicographically_first_natively_accepted_committed_candidate",
        "timeout_sec": args.timeout_sec,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(_canonical_bytes(manifest) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
