#!/usr/bin/env python
"""Regenerate README / docs/BACKENDS.md capability tables from the adapter registry."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.adapter_conformance import apply_release_status_honesty  # noqa: E402
from ovk.core.capabilities import CapabilityRegistry  # noqa: E402
from ovk.core.json_io import read_json_file  # noqa: E402

BEGIN_BACKENDS = "<!-- BEGIN OVK_CAPABILITY_TABLE -->"
END_BACKENDS = "<!-- END OVK_CAPABILITY_TABLE -->"
BEGIN_README = "<!-- BEGIN OVK_CAPABILITY_TABLE -->"
END_README = "<!-- END OVK_CAPABILITY_TABLE -->"

BACKEND_ORDER = (
    "opa",
    "z3",
    "cbmc",
    "cedar",
    "tla+",
    "kani",
    "dafny",
    "verus",
    "lean",
    "alloy",
)


def _display_backend(checker_id: str) -> str:
    return f"`{checker_id}`"


def _execution_summary(manifest: dict[str, Any]) -> str:
    native = manifest.get("native_execution")
    determinism = manifest.get("determinism_status", "unknown")
    if native is True:
        return f"Native path available ({determinism})"
    if native is False:
        return f"Deterministic contract evaluator only ({determinism})"
    return f"Execution maturity undocumented ({determinism})"


def _native_determines_evidence(manifest: dict[str, Any]) -> str:
    return "Yes" if manifest.get("native_execution") is True else "No"


def _current_limit(manifest: dict[str, Any]) -> str:
    unsupported = str(manifest.get("unsupported_semantics") or "").strip()
    if unsupported:
        # Keep table cells readable.
        first = unsupported.split(";")[0].strip()
        return first
    limits = manifest.get("limits") or []
    if limits:
        return str(limits[0])
    return "See capability manifest"


def render_backends_table(manifests: list[dict[str, Any]]) -> str:
    by_checker = {str(m.get("checker_id") or m.get("tool", {}).get("name")): m for m in manifests}
    lines = [
        "| Backend | release_status | Current execution | Native result can determine evidence? | Current limit |",
        "|---|---|---|---:|---|",
    ]
    ordered = [cid for cid in BACKEND_ORDER if cid in by_checker]
    ordered.extend(sorted(cid for cid in by_checker if cid not in BACKEND_ORDER))
    for checker_id in ordered:
        manifest = by_checker[checker_id]
        lines.append(
            "| "
            + " | ".join(
                [
                    _display_backend(checker_id),
                    str(manifest.get("release_status", "experimental")),
                    _execution_summary(manifest),
                    _native_determines_evidence(manifest),
                    _current_limit(manifest),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def render_readme_table(manifests: list[dict[str, Any]]) -> str:
    by_checker = {str(m.get("checker_id") or m.get("tool", {}).get("name")): m for m in manifests}
    lines = [
        "| Checker | release_status | claim_class | Native execution |",
        "|---|---|---|---|",
    ]
    ordered = [cid for cid in BACKEND_ORDER if cid in by_checker]
    ordered.extend(sorted(cid for cid in by_checker if cid not in BACKEND_ORDER))
    for checker_id in ordered:
        manifest = by_checker[checker_id]
        native = "yes" if manifest.get("native_execution") is True else "no"
        lines.append(
            "| "
            + " | ".join(
                [
                    _display_backend(checker_id),
                    str(manifest.get("release_status", "experimental")),
                    str(manifest.get("claim_class", "")),
                    native,
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _replace_marked_section(text: str, begin: str, end: str, body: str) -> str:
    if begin not in text or end not in text:
        raise ValueError(f"missing markers {begin!r} / {end!r}")
    before, rest = text.split(begin, 1)
    _, after = rest.split(end, 1)
    return f"{before}{begin}\n{body}\n{end}{after}"


def load_manifests(repo_root: Path) -> list[dict[str, Any]]:
    adapters = repo_root / "adapters"
    registry = CapabilityRegistry.from_directory(adapters, validate=True)
    manifests = registry.all()
    if not manifests:
        # Fallback for packaged layouts that sync capability files.
        manifests = [
            read_json_file(path)
            for path in sorted(adapters.glob("*/capability.json"))
        ]
    # Auto-downgrade non-conformant adapters that claim stable (OVK-PR4).
    return [apply_release_status_honesty(m, root=repo_root) for m in manifests]


def main() -> int:
    parser = argparse.ArgumentParser(description="Render capability tables from the adapter registry")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when README / BACKENDS.md tables are stale",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write regenerated tables into README.md and docs/BACKENDS.md",
    )
    args = parser.parse_args()
    if not args.check and not args.write:
        args.write = True

    repo_root = args.repo_root.resolve()
    manifests = load_manifests(repo_root)
    backends_body = render_backends_table(manifests)
    readme_body = (
        "Public checkers from the normative capability registry "
        "(`adapters/*/capability.json`). Tables are generated by "
        "`scripts/render_capability_tables.py`.\n\n"
        + render_readme_table(manifests)
        + "\n\nDetails and fallback rules: [docs/BACKENDS.md](docs/BACKENDS.md)."
    )

    backends_path = repo_root / "docs" / "BACKENDS.md"
    readme_path = repo_root / "README.md"
    backends_text = backends_path.read_text(encoding="utf-8")
    readme_text = readme_path.read_text(encoding="utf-8")

    new_backends = _replace_marked_section(backends_text, BEGIN_BACKENDS, END_BACKENDS, backends_body)
    new_readme = _replace_marked_section(readme_text, BEGIN_README, END_README, readme_body)

    stale = False
    if new_backends != backends_text:
        stale = True
        if args.write:
            backends_path.write_text(new_backends, encoding="utf-8")
            print(f"updated {backends_path}")
        else:
            print(f"stale: {backends_path}", file=sys.stderr)
    else:
        print(f"up to date: {backends_path}")

    if new_readme != readme_text:
        stale = True
        if args.write:
            readme_path.write_text(new_readme, encoding="utf-8")
            print(f"updated {readme_path}")
        else:
            print(f"stale: {readme_path}", file=sys.stderr)
    else:
        print(f"up to date: {readme_path}")

    if args.check and stale:
        print("capability tables are stale; run: python scripts/render_capability_tables.py --write", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
