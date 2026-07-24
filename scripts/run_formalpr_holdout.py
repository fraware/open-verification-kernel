#!/usr/bin/env python3
"""Download a frozen FormalPR-Holdout release and emit aggregate metrics only.

Fail-closed: never prints protected labels or case ids. Ordinary OVK CI should
not invoke this without HOLDOUT_DOWNLOAD_TOKEN (or a pre-fetched artifact).

Supply-chain requirements:
- immutable SHA-256 of the release asset must be supplied and verified;
- archive extraction is path-safe (no links, devices, FIFOs, or traversal);
- evaluate.py runs with an isolated env that excludes GitHub/holdout tokens;
- aggregate output is schema-validated and leakage-guarded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


FORBIDDEN_SUBSTRINGS = (
    "expected_status",
    "expected_merge_recommendation",
    "ground_truth_class",
    "true_positive_unsafe",
    "true_negative_safe",
    "syn-auth-bypass-01",
    "syn-auth-safe-01",
    "syn-ci-secrets-leak-01",
    "syn-ci-secrets-safe-01",
    "syn-infra-exposure-01",
    "syn-invalid-input-01",
    "syn-unknown-surface-01",
)

_TOKEN_ENV_KEYS = frozenset(
    {
        "HOLDOUT_DOWNLOAD_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_REQUIRED_AGGREGATE_KEYS = (
    "schema_version",
    "benchmark",
    "holdout_release_tag",
    "ovk_commit_sha",
    "cases_scored",
    "lanes",
    "leakage_guard",
)


def _fail(msg: str) -> None:
    raise SystemExit(f"fail-closed: {msg}")


def assert_aggregate_safe(payload: dict[str, Any]) -> None:
    text = json.dumps(payload)
    for token in FORBIDDEN_SUBSTRINGS:
        if token in text:
            _fail(f"aggregate output contains protected token {token!r}")
    if payload.get("leakage_guard", {}).get("labels_emitted") is not False:
        _fail("leakage_guard.labels_emitted must be false")
    if payload.get("leakage_guard", {}).get("case_ids_emitted") is not False:
        _fail("leakage_guard.case_ids_emitted must be false")
    if "lanes" not in payload:
        _fail("aggregate missing lanes")
    # Refuse single pass-rate collapse as the only metric surface.
    if set(payload.keys()) <= {"pass_rate", "schema_version", "benchmark"}:
        _fail("refusing pass-rate-only payload")


def validate_aggregate_schema(payload: dict[str, Any]) -> None:
    """Fail-closed structural validation for holdout aggregate metrics."""
    for key in _REQUIRED_AGGREGATE_KEYS:
        if key not in payload:
            _fail(f"aggregate missing required key {key!r}")
    if payload.get("schema_version") != "formalpr_holdout.aggregate_metrics.v1":
        _fail("unexpected aggregate schema_version")
    if payload.get("benchmark") != "FormalPR-Holdout":
        _fail("unexpected aggregate benchmark")
    lanes = payload.get("lanes")
    if not isinstance(lanes, dict) or not lanes:
        _fail("aggregate lanes must be a non-empty object")
    for lane, metrics in lanes.items():
        if not isinstance(metrics, dict):
            _fail(f"lane {lane!r} metrics must be an object")
        for key in (
            "precision",
            "recall",
            "false_positive_rate",
            "missed_detection_rate",
            "unknown_rate",
            "coverage_completeness",
            "counterexample_correctness",
            "selected_backend_execution_correctness",
            "runtime_ms",
        ):
            if key not in metrics:
                _fail(f"missing {key} in lane {lane}")
    assert_aggregate_safe(payload)


def download_release_asset(
    *,
    repo: str,
    tag: str,
    asset_name: str,
    dest: Path,
    token: str | None,
) -> Path:
    api = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(api, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            release = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        _fail(f"cannot read release {tag} from {repo}: HTTP {exc.code}")

    asset = next((a for a in release.get("assets", []) if a.get("name") == asset_name), None)
    if asset is None:
        _fail(f"asset {asset_name!r} not found on release {tag}")

    url = asset["url"]
    asset_headers = {
        "Accept": "application/octet-stream",
        **({"Authorization": f"Bearer {token}"} if token else {}),
    }
    areq = urllib.request.Request(url, headers=asset_headers)
    try:
        with urllib.request.urlopen(areq, timeout=120) as resp:
            dest.write_bytes(resp.read())
    except urllib.error.HTTPError as exc:
        _fail(f"cannot download asset {asset_name!r}: HTTP {exc.code}")
    return dest


def verify_asset_sha256(path: Path, expected_sha256: str) -> str:
    if not _SHA256_RE.match(expected_sha256):
        _fail("asset SHA-256 must be a 64-character hex digest")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest.lower() != expected_sha256.lower():
        _fail("asset SHA-256 mismatch")
    return digest


def _is_unsafe_tar_member(member: tarfile.TarInfo) -> str | None:
    name = member.name.replace("\\", "/")
    if name.startswith("/") or name.startswith("..") or "/../" in f"/{name}/":
        return f"unsafe path {member.name!r}"
    if member.issym() or member.islnk():
        return f"link member forbidden: {member.name!r}"
    if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
        return f"special file forbidden: {member.name!r}"
    # Reject unusual types beyond regular files and directories.
    if not (member.isfile() or member.isdir()):
        return f"unsupported member type: {member.name!r}"
    return None


def extract_tarball(tarball: Path, dest: Path) -> Path:
    """Path-safe extraction: no links/devices/FIFOs/traversal; no filter=data reliance."""
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    with tarfile.open(tarball, "r:gz") as tar:
        for member in tar.getmembers():
            reason = _is_unsafe_tar_member(member)
            if reason:
                _fail(reason)
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest_resolved) + os.sep) and target != dest_resolved:
                _fail(f"path traversal forbidden: {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tar.extractfile(member)
            if extracted is None:
                _fail(f"cannot extract member {member.name!r}")
            with extracted, open(target, "wb") as out:
                out.write(extracted.read())
            # Ensure we did not create a link somehow.
            if target.is_symlink() or not target.is_file():
                _fail(f"extracted path is not a regular file: {member.name!r}")
            mode = target.stat().st_mode
            if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode):
                _fail(f"special file after extract: {member.name!r}")
    roots = [p for p in dest.iterdir() if p.is_dir()]
    if len(roots) != 1:
        _fail(f"expected one release root, found {len(roots)}")
    return roots[0]


def _isolated_eval_env() -> dict[str, str]:
    """Build an evaluator environment without download/GitHub tokens."""
    allow = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "LANG",
        "LC_ALL",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "PYTHONNOUSERSITE",
        "PYTHONUTF8",
        "PYTHONIOENCODING",
    }
    env = {k: v for k, v in os.environ.items() if k.upper() in allow}
    env["PYTHONNOUSERSITE"] = "1"
    for key in list(env):
        if key.upper() in _TOKEN_ENV_KEYS:
            env.pop(key, None)
    # Explicitly ensure tokens are absent even if allowlist was widened later.
    for denied in _TOKEN_ENV_KEYS:
        env.pop(denied, None)
    return env


def run_harness(
    *,
    release_root: Path,
    predictions: Path,
    holdout_tag: str,
    ovk_sha: str,
    verified_sha: str | None,
    output: Path,
) -> dict[str, Any]:
    evaluate = release_root / "harness" / "evaluate.py"
    if not evaluate.is_file():
        _fail("release artifact missing harness/evaluate.py")
    # Preferred layout: corpus/cases + corpus/labels (v0.1.0+).
    # Legacy fallback: cases/ + labels/ at release root.
    if (release_root / "corpus" / "cases").is_dir():
        corpus_root = release_root / "corpus"
        labels_dir = release_root / "corpus" / "labels"
    elif (release_root / "cases").is_dir():
        corpus_root = release_root
        labels_dir = release_root / "labels"
    else:
        _fail("release artifact missing corpus/cases or cases/")

    cmd = [
        sys.executable,
        str(evaluate),
        "--corpus-root",
        str(corpus_root),
        "--labels-dir",
        str(labels_dir),
        "--predictions",
        str(predictions),
        "--holdout-release-tag",
        holdout_tag,
        "--ovk-commit-sha",
        ovk_sha,
        "--output",
        str(output),
    ]
    if verified_sha:
        cmd.extend(["--verified-source-sha", verified_sha])
    # Do not pass --print-aggregates; we load the file and re-sanitize.
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        env=_isolated_eval_env(),
        cwd=str(release_root),
    )
    if proc.returncode != 0:
        # Avoid echoing stderr if it might contain paths with case ids — redact.
        _fail(f"evaluate.py exited {proc.returncode}")
    payload = json.loads(output.read_text(encoding="utf-8"))
    validate_aggregate_schema(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run FormalPR-Holdout aggregate eval")
    parser.add_argument("--repo", default="fraware/FormalPR-Holdout")
    parser.add_argument("--tag", default="v0.1.0-synthetic")
    parser.add_argument(
        "--asset-name",
        default=None,
        help="Defaults to FormalPR-Holdout-<tag>.tar.gz",
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        default=None,
        help="Use a pre-downloaded tarball instead of GitHub API download",
    )
    parser.add_argument(
        "--asset-sha256",
        required=True,
        help="Immutable SHA-256 hex digest of the release asset (required)",
    )
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ovk-commit-sha", required=True)
    parser.add_argument("--verified-source-sha", default=None)
    parser.add_argument(
        "--print-aggregates",
        action="store_true",
        help="Print sanitized aggregates to stdout after fail-closed checks",
    )
    args = parser.parse_args(argv)

    token = os.environ.get("HOLDOUT_DOWNLOAD_TOKEN") or os.environ.get("GITHUB_TOKEN")
    asset_name = args.asset_name or f"FormalPR-Holdout-{args.tag}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="ovk-holdout-") as tmp:
        tmp_path = Path(tmp)
        if args.artifact:
            tarball = args.artifact
            if not tarball.is_file():
                _fail(f"artifact not found: {tarball}")
        else:
            if not token:
                _fail(
                    "HOLDOUT_DOWNLOAD_TOKEN (or GITHUB_TOKEN) required to download "
                    "private FormalPR-Holdout release assets"
                )
            tarball = download_release_asset(
                repo=args.repo,
                tag=args.tag,
                asset_name=asset_name,
                dest=tmp_path / asset_name,
                token=token,
            )
        verify_asset_sha256(tarball, args.asset_sha256)
        release_root = extract_tarball(tarball, tmp_path / "extract")
        # Predictions must be label-free before the evaluator sees them.
        pred_payload = json.loads(args.predictions.read_text(encoding="utf-8"))
        from scripts.digest_holdout_predictions import assert_predictions_label_free

        assert_predictions_label_free(pred_payload)
        payload = run_harness(
            release_root=release_root,
            predictions=args.predictions,
            holdout_tag=args.tag,
            ovk_sha=args.ovk_commit_sha,
            verified_sha=args.verified_source_sha,
            output=tmp_path / "aggregate.json",
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    summary = (
        f"FormalPR-Holdout aggregates ok: {payload.get('cases_scored')} cases, "
        f"{len(payload.get('lanes', {}))} lanes, tag={args.tag}. Labels not emitted."
    )
    print(summary)
    if args.print_aggregates:
        validate_aggregate_schema(payload)
        print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
