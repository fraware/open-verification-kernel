#!/usr/bin/env python3
"""Download a frozen FormalPR-Holdout release and emit aggregate metrics only.

Fail-closed properties:

* remote release assets require an independently supplied SHA-256 digest;
* archive extraction rejects path traversal, links, devices, and special files;
* the downloaded evaluator runs with a minimal environment that contains no
  GitHub or holdout download token;
* aggregate output is validated against the public schema and inspected for
  protected fields before it is written or printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
AGGREGATE_SCHEMA = ROOT / "schemas" / "holdout.aggregate_metrics.schema.json"

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
FORBIDDEN_KEY_FRAGMENTS = (
    "case_id",
    "case_ids",
    "expected_",
    "ground_truth",
    "label",
    "diff_text",
    "counterexample_text",
)


def _fail(msg: str) -> None:
    raise SystemExit(f"fail-closed: {msg}")


def _walk_keys(value: Any, *, path: str = "$") -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if any(fragment in lowered for fragment in FORBIDDEN_KEY_FRAGMENTS):
                findings.append((f"{path}.{key_text}", key_text))
            findings.extend(_walk_keys(child, path=f"{path}.{key_text}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_walk_keys(child, path=f"{path}[{index}]"))
    return findings


def _schema_errors(payload: dict[str, Any]) -> list[str]:
    if not AGGREGATE_SCHEMA.is_file():
        return [f"aggregate schema missing: {AGGREGATE_SCHEMA}"]
    schema = json.loads(AGGREGATE_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '$'}: {error.message}"
        for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.absolute_path))
    ]


def assert_aggregate_safe(payload: dict[str, Any]) -> None:
    schema_errors = _schema_errors(payload)
    if schema_errors:
        _fail("aggregate schema validation failed: " + "; ".join(schema_errors))

    text = json.dumps(payload, sort_keys=True)
    for token in FORBIDDEN_SUBSTRINGS:
        if token in text:
            _fail(f"aggregate output contains protected token {token!r}")

    forbidden_keys = _walk_keys(payload)
    if forbidden_keys:
        rendered = ", ".join(path for path, _key in forbidden_keys)
        _fail(f"aggregate output contains protected field names: {rendered}")

    leakage = payload.get("leakage_guard", {})
    if leakage.get("labels_emitted") is not False:
        _fail("leakage_guard.labels_emitted must be false")
    if leakage.get("case_ids_emitted") is not False:
        _fail("leakage_guard.case_ids_emitted must be false")
    if leakage.get("fail_closed") is not True:
        _fail("leakage_guard.fail_closed must be true")

    reviewer_time = payload.get("reviewer_time")
    if isinstance(reviewer_time, dict) and reviewer_time.get("notes"):
        _fail("reviewer_time.notes is not permitted in public aggregate output")

    if "lanes" not in payload:
        _fail("aggregate missing lanes")
    if set(payload.keys()) <= {"pass_rate", "schema_version", "benchmark"}:
        _fail("refusing pass-rate-only payload")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_asset_digest(path: Path, expected_sha256: str | None) -> str:
    actual = sha256_file(path)
    expected = (expected_sha256 or "").strip().lower()
    if expected:
        if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
            _fail("asset SHA-256 must contain exactly 64 hexadecimal characters")
        if actual != expected:
            _fail(f"holdout asset digest mismatch: expected {expected}, got {actual}")
    return actual


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

    if str(release.get("tag_name", "")) != tag:
        _fail(f"release API returned unexpected tag {release.get('tag_name')!r}")
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


def _safe_member_target(dest: Path, member_name: str) -> Path:
    pure = PurePosixPath(member_name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        _fail(f"unsafe archive member path: {member_name!r}")
    target = (dest / Path(*pure.parts)).resolve()
    try:
        target.relative_to(dest.resolve())
    except ValueError:
        _fail(f"archive member escapes extraction root: {member_name!r}")
    return target


def extract_tarball(tarball: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tar:
        members = tar.getmembers()
        if not members:
            _fail("holdout release archive is empty")
        for member in members:
            target = _safe_member_target(dest, member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                _fail(f"archive contains forbidden special member: {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                _fail(f"archive contains unsupported member type: {member.name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                _fail(f"cannot read archive member: {member.name!r}")
            with source, target.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)

    roots = [path for path in dest.iterdir() if path.is_dir()]
    if len(roots) != 1:
        _fail(f"expected one release root, found {len(roots)}")
    return roots[0]


def _harness_environment(home: Path) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True)
    env = {
        "HOME": str(home),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    # Deliberately omit GITHUB_TOKEN, HOLDOUT_DOWNLOAD_TOKEN, cloud credentials,
    # signing keys, and every other inherited variable.
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
    if (release_root / "corpus" / "cases").is_dir():
        corpus_root = release_root / "corpus"
        labels_dir = release_root / "corpus" / "labels"
    elif (release_root / "cases").is_dir():
        corpus_root = release_root
        labels_dir = release_root / "labels"
    else:
        _fail("release artifact missing corpus/cases or cases/")
    if not labels_dir.is_dir():
        _fail("release artifact missing labels directory")

    cmd = [
        sys.executable,
        "-I",
        str(evaluate),
        "--corpus-root",
        str(corpus_root),
        "--labels-dir",
        str(labels_dir),
        "--predictions",
        str(predictions.resolve()),
        "--holdout-release-tag",
        holdout_tag,
        "--ovk-commit-sha",
        ovk_sha,
        "--output",
        str(output.resolve()),
    ]
    if verified_sha:
        cmd.extend(["--verified-source-sha", verified_sha])

    proc = subprocess.run(
        cmd,
        cwd=str(release_root),
        env=_harness_environment(output.parent / "harness-home"),
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    if proc.returncode != 0:
        _fail(f"evaluate.py exited {proc.returncode}")
    if not output.is_file():
        _fail("evaluate.py did not produce aggregate output")
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert_aggregate_safe(payload)
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
        "--asset-sha256",
        default=None,
        help="Expected immutable SHA-256. Required for remote downloads.",
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        default=None,
        help="Use a pre-downloaded tarball instead of GitHub API download",
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
    expected_digest = args.asset_sha256 or os.environ.get("HOLDOUT_ASSET_SHA256")

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
            if not expected_digest:
                _fail("HOLDOUT_ASSET_SHA256 or --asset-sha256 is required for remote holdout assets")
            tarball = download_release_asset(
                repo=args.repo,
                tag=args.tag,
                asset_name=asset_name,
                dest=tmp_path / asset_name,
                token=token,
            )
        verify_asset_digest(tarball, expected_digest)
        release_root = extract_tarball(tarball, tmp_path / "extract")
        payload = run_harness(
            release_root=release_root,
            predictions=args.predictions,
            holdout_tag=args.tag,
            ovk_sha=args.ovk_commit_sha,
            verified_sha=args.verified_source_sha,
            output=tmp_path / "aggregate.json",
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = (
        f"FormalPR-Holdout aggregates ok: {payload.get('cases_scored')} cases, "
        f"{len(payload.get('lanes', {}))} lanes, tag={args.tag}. Labels not emitted."
    )
    print(summary)
    if args.print_aggregates:
        assert_aggregate_safe(payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
