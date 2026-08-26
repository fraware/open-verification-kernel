#!/usr/bin/env python
"""Check whether a PyPI version is absent or exactly matches local distributions.

Before Trusted Publishing, ``absent`` or ``exact_match`` are safe states. After
publication, callers use ``--require-exact`` so only an exact filename and
SHA-256 match is accepted. This makes recovery after a partial PyPI/GitHub
publication failure idempotent without a blind ``skip-existing`` policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_distribution_files(dist_dir: Path) -> dict[str, str]:
    """Return the exact release filename->SHA256 map, requiring one wheel/sdist."""
    wheels = sorted(path for path in dist_dir.glob("*.whl") if path.is_file())
    sdists = sorted(path for path in dist_dir.glob("*.tar.gz") if path.is_file())
    if len(wheels) != 1:
        raise ValueError(f"expected exactly one wheel, found {len(wheels)}")
    if len(sdists) != 1:
        raise ValueError(f"expected exactly one sdist, found {len(sdists)}")
    return {
        wheels[0].name: _sha256(wheels[0]),
        sdists[0].name: _sha256(sdists[0]),
    }


def compare_pypi_payload(
    payload: Mapping[str, Any],
    *,
    local_files: Mapping[str, str],
) -> dict[str, Any]:
    """Compare one PyPI release JSON payload with the authorized local file set."""
    urls = payload.get("urls")
    if not isinstance(urls, list):
        return {
            "state": "conflict",
            "failures": ["PyPI payload missing urls list"],
            "local_files": dict(sorted(local_files.items())),
            "remote_files": {},
        }

    remote: dict[str, str] = {}
    failures: list[str] = []
    for row in urls:
        if not isinstance(row, Mapping):
            failures.append("PyPI urls entry is not an object")
            continue
        filename = str(row.get("filename") or "")
        digests = row.get("digests")
        sha = str(digests.get("sha256") or "").lower() if isinstance(digests, Mapping) else ""
        if not filename:
            failures.append("PyPI file missing filename")
            continue
        if filename in remote:
            failures.append(f"duplicate PyPI filename: {filename}")
            continue
        if len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
            failures.append(f"PyPI file has malformed SHA-256: {filename}")
            continue
        remote[filename] = sha

    local = {str(name): str(digest).lower() for name, digest in local_files.items()}
    missing = sorted(set(local) - set(remote))
    unexpected = sorted(set(remote) - set(local))
    mismatched = sorted(
        name for name in set(local) & set(remote) if local[name] != remote[name]
    )
    failures.extend(f"missing PyPI file: {name}" for name in missing)
    failures.extend(f"unexpected PyPI file: {name}" for name in unexpected)
    failures.extend(f"PyPI digest mismatch: {name}" for name in mismatched)

    return {
        "state": "exact_match" if not failures else "conflict",
        "failures": failures,
        "local_files": dict(sorted(local.items())),
        "remote_files": dict(sorted(remote.items())),
    }


def publication_state_allowed(result: Mapping[str, Any], *, require_exact: bool) -> bool:
    """Return whether a PyPI state is safe for the requested release phase."""
    state = result.get("state")
    if require_exact:
        return state == "exact_match"
    return state in {"absent", "exact_match"}


def inspect_pypi_state(
    *,
    project: str,
    version: str,
    dist_dir: Path,
    timeout: int = 30,
) -> dict[str, Any]:
    """Query PyPI and return absent, exact_match, or conflict."""
    local = local_distribution_files(dist_dir)
    endpoint = (
        "https://pypi.org/pypi/"
        f"{quote(project, safe='')}/{quote(version, safe='')}/json"
    )
    request = urllib.request.Request(
        endpoint,
        headers={"Accept": "application/json", "User-Agent": "ovk-release-verifier/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "state": "absent",
                "failures": [],
                "local_files": dict(sorted(local.items())),
                "remote_files": {},
            }
        raise RuntimeError(f"PyPI lookup failed with HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"PyPI lookup failed: {exc}") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("PyPI returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("PyPI returned a non-object JSON payload")
    return compare_pypi_payload(payload, local_files=local)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="open-verification-kernel")
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--require-exact",
        action="store_true",
        help="Require PyPI to contain exactly the local authorized wheel and sdist.",
    )
    args = parser.parse_args(argv)

    try:
        result = inspect_pypi_state(
            project=args.project,
            version=args.version,
            dist_dir=args.dist_dir.resolve(),
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"pypi_state_verification_failed:{exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for failure in result.get("failures") or []:
        print(failure, file=sys.stderr)
    if not publication_state_allowed(result, require_exact=args.require_exact):
        if result.get("state") == "absent" and args.require_exact:
            print("PyPI version is still absent but exact published state is required", file=sys.stderr)
        return 1
    print(f"PyPI state: {result['state']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
