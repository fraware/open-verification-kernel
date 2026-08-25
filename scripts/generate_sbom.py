#!/usr/bin/env python
"""Generate a CycloneDX-like SBOM stub for local wheel builds (WP-16 hygiene).

Does not publish. Records package digests when dist/ artifacts exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate local wheel SBOM digests")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--dist", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    dist = (args.dist or (repo / "dist")).resolve()
    output = (args.output or (repo / ".verification" / "sbom.cdx.json")).resolve()

    components: list[dict] = []
    wheel_sha = None
    sdist_sha = None
    if dist.is_dir():
        for path in sorted(dist.glob("*.whl")):
            digest = _sha256(path)
            wheel_sha = digest
            components.append(
                {
                    "type": "library",
                    "name": path.name,
                    "version": None,
                    "hashes": [{"alg": "SHA-256", "content": digest}],
                }
            )
            (dist / ".wheel-sha256").write_text(digest + "\n", encoding="utf-8")
        for path in sorted(dist.glob("*.tar.gz")):
            digest = _sha256(path)
            sdist_sha = digest
            components.append(
                {
                    "type": "library",
                    "name": path.name,
                    "version": None,
                    "hashes": [{"alg": "SHA-256", "content": digest}],
                }
            )
            (dist / ".sdist-sha256").write_text(digest + "\n", encoding="utf-8")

    lock = repo / "toolchains" / "backend-tools.lock.json"
    toolchain_sha = _sha256(lock) if lock.is_file() else None
    if toolchain_sha:
        components.append(
            {
                "type": "file",
                "name": "toolchains/backend-tools.lock.json",
                "hashes": [{"alg": "SHA-256", "content": toolchain_sha}],
            }
        )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "ovk.scripts.generate_sbom", "version": "1"}],
            "component": {
                "type": "library",
                "name": "open-verification-kernel",
                "version": None,
            },
        },
        "components": components,
        "ovk_extension": {
            "wheel_sha256": wheel_sha,
            "sdist_sha256": sdist_sha,
            "toolchain_lock_sha256": toolchain_sha,
            "note": "Local SBOM stub for ledger fields; not a signed release attestation.",
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(sbom, indent=2, sort_keys=True) + "\n"
    output.write_text(raw, encoding="utf-8")
    print(f"sbom -> {output} sha256={hashlib.sha256(raw.encode()).hexdigest()}")
    if not components:
        print("note: no dist wheels/sdists found; toolchain lock digest recorded only", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
