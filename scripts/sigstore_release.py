#!/usr/bin/env python
"""CLI for protected-release keyless Sigstore signing."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from ovk.core.sigstore_release import (
    DEFAULT_OIDC_ISSUER,
    discover_release_artifacts,
    github_certificate_identity,
    sign_and_verify_release,
    write_summary,
)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--extra", type=Path, action="append", default=[])
    parser.add_argument("--bundles-dir", type=Path, default=Path("sigstore-bundles"))
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("sigstore-bundles/ovk-sigstore-summary.json"),
    )
    parser.add_argument("--certificate-identity", default="")
    parser.add_argument("--certificate-oidc-issuer", default=DEFAULT_OIDC_ISSUER)
    parser.add_argument("--require-immutable-tag", action="store_true")
    parser.add_argument("--git-ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--print-identity-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    identity = args.certificate_identity.strip() or github_certificate_identity()
    issuer = args.certificate_oidc_issuer.strip() or DEFAULT_OIDC_ISSUER

    if args.print_identity_only:
        print(identity)
        return 0

    artifacts = discover_release_artifacts(args.dist_dir, args.extra)
    signed = sign_and_verify_release(
        artifacts,
        bundles_dir=args.bundles_dir,
        certificate_identity=identity,
        certificate_oidc_issuer=issuer,
        require_tag=args.require_immutable_tag,
        git_ref=args.git_ref,
    )
    summary = write_summary(args.summary, identity=identity, issuer=issuer, signed=signed)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 - CLI boundary
        print(f"sigstore_release: {error}", file=sys.stderr)
        raise SystemExit(1) from error
