#!/usr/bin/env python
"""Generate .verification/project-status.json and claim-registry.json."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.project_status import write_project_status_and_claims  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build project-status and claim registry")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--candidate-sha", default=None)
    args = parser.parse_args()
    claims, status = write_project_status_and_claims(
        args.repo_root.resolve(),
        candidate_sha=args.candidate_sha,
    )
    print(f"claims={claims['claim_count']} candidate={status['candidate_sha']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
