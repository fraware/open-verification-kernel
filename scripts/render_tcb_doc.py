#!/usr/bin/env python
"""Generate docs/TRUSTED_COMPUTING_BASE.md from registry trusted_components + surfaces.

Independent reviewers use the generated document to identify the OVK TCB
(OVK-PR9 / program DoD). Prefer regenerating over hand-editing the markdown body.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.adapter_conformance import ADVERTISED_ADAPTER_IDS, apply_release_status_honesty  # noqa: E402
from ovk.core.capabilities import CapabilityRegistry  # noqa: E402
from ovk.core.release_metadata import OVK_RELEASE_CANDIDATE  # noqa: E402
from scripts.pin_action_shas import DEFAULT_PATHS as ACTION_PIN_PATHS  # noqa: E402
from scripts.pin_action_shas import floating_uses_in_file, is_local_action, is_sha_pinned  # noqa: E402

BEGIN = "<!-- BEGIN OVK_TCB_GENERATED -->"
END = "<!-- END OVK_TCB_GENERATED -->"

USES_COMMENT_RE = re.compile(
    r"""^\s*(?:-\s*)?uses:\s*['"]?(?P<action>[^'"\s#]+)['"]?\s*(?:#\s*(?P<label>.*))?$""",
    re.MULTILINE,
)


def _load_manifests(repo_root: Path) -> list[dict[str, Any]]:
    registry = CapabilityRegistry.from_directory(repo_root / "adapters", validate=True)
    return [apply_release_status_honesty(dict(m), root=repo_root) for m in registry.all()]


def _checker_id(manifest: dict[str, Any]) -> str:
    return str(manifest.get("checker_id") or manifest.get("tool", {}).get("name") or "unknown")


def _action_pins(repo_root: Path) -> list[tuple[str, str, str]]:
    """Return (path, uses_ref, comment_label) for SHA-pinned third-party actions."""
    rows: list[tuple[str, str, str]] = []
    for path in ACTION_PIN_PATHS:
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8")
        for match in USES_COMMENT_RE.finditer(text):
            ref = match.group("action")
            if is_local_action(ref):
                continue
            label = (match.group("label") or "").strip()
            rows.append((rel, ref, label))
    return rows


def _github_app_controls(repo_root: Path) -> list[tuple[str, str]]:
    readme = repo_root / "integrations" / "github-app" / "README.md"
    if not readme.exists():
        return []
    text = readme.read_text(encoding="utf-8")
    rows: list[tuple[str, str]] = []
    in_table = False
    for line in text.splitlines():
        if line.startswith("| Control |"):
            in_table = True
            continue
        if in_table and line.startswith("|---"):
            continue
        if in_table and line.startswith("|") and "|" in line[1:]:
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) >= 2 and cells[0] and cells[0] != "Control":
                rows.append((cells[0], cells[1]))
            continue
        if in_table and not line.startswith("|"):
            break
    return rows


def render_tcb_body(repo_root: Path) -> str:
    manifests = _load_manifests(repo_root)
    by_id = {_checker_id(m): m for m in manifests}
    missing = [cid for cid in ADVERTISED_ADAPTER_IDS if cid not in by_id]

    lines: list[str] = [
        f"Generated for package version **`{OVK_RELEASE_CANDIDATE}`** by "
        "`scripts/render_tcb_doc.py`. Do not hand-edit this section; regenerate with "
        "`python scripts/render_tcb_doc.py --write`.",
        "",
        "## Package identity",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Package version | `{OVK_RELEASE_CANDIDATE}` |",
        f"| Intended immutable tag | `v{OVK_RELEASE_CANDIDATE}` |",
        "| Public integration path | Composite Action (`action.yml`) + `pip` wheel |",
        "| Private alpha path | `integrations/github-app/` (not Marketplace) |",
        "",
        "## Composite Action surface",
        "",
        "Third-party actions in release paths must be immutable SHA pins "
        "(enforced by `scripts/pin_action_shas.py`):",
        "",
        "| File | `uses:` pin | Note |",
        "|---|---|---|",
    ]
    for rel, ref, label in _action_pins(repo_root):
        note = label or ("SHA-pinned" if is_sha_pinned(ref) else "UNPINNED")
        lines.append(f"| `{rel}` | `{ref}` | {note} |")
    if not _action_pins(repo_root):
        lines.append("| — | — | no third-party uses found |")

    floating = []
    for path in ACTION_PIN_PATHS:
        floating.extend(floating_uses_in_file(path))
    lines.extend(
        [
            "",
            f"Floating third-party refs in release paths: **{len(floating)}** "
            f"(must be zero for RC).",
            "",
            "Action install trust boundary:",
            "",
            "- Runner installs `open-verification-kernel==$OVK_PACKAGE_VERSION` when set,",
            "  otherwise installs from the Action checkout after `scripts/sync_package_data.py`.",
            "- Consumer repositories must pin the Action to an immutable tag or full commit SHA.",
            "- Check-run emission uses a stable `external_id` bound to repository + head SHA.",
            "",
            "## GitHub App surface (private alpha)",
            "",
            "The App is **not** part of the default public TCB for adopters who only use "
            "the composite Action. Operators who deploy the App additionally trust:",
            "",
            "| Control | Implementation |",
            "|---|---|",
        ]
    )
    app_rows = _github_app_controls(repo_root)
    if app_rows:
        for control, impl in app_rows:
            lines.append(f"| {control} | {impl} |")
    else:
        lines.append("| — | See `integrations/github-app/README.md` |")
    lines.extend(
        [
            "",
            "App code and retention policy: [`integrations/github-app/`](../integrations/github-app/).",
            "",
            "## Capability registry trusted components",
            "",
            "Every advertised public checker contributes the `trusted_components` list from "
            "its `adapters/*/capability.json` entry (after release-status honesty).",
            "",
        ]
    )
    if missing:
        lines.append(
            "**Registry coverage gap:** missing capability entries for: "
            + ", ".join(f"`{cid}`" for cid in missing)
        )
        lines.append("")

    lines.extend(
        [
            "| Checker | release_status | Trusted components |",
            "|---|---|---|",
        ]
    )
    ordered = [cid for cid in ADVERTISED_ADAPTER_IDS if cid in by_id]
    ordered.extend(sorted(cid for cid in by_id if cid not in ADVERTISED_ADAPTER_IDS))
    for checker_id in ordered:
        manifest = by_id[checker_id]
        status = str(manifest.get("release_status") or "unknown")
        components = manifest.get("trusted_components") or []
        if isinstance(components, list):
            rendered = "; ".join(str(c) for c in components) if components else "_(none listed)_"
        else:
            rendered = str(components)
        lines.append(f"| `{checker_id}` | `{status}` | {rendered} |")

    # Aggregate unique TCB component names for reviewers scanning once.
    unique: list[str] = []
    seen: set[str] = set()
    for checker_id in ordered:
        for item in by_id[checker_id].get("trusted_components") or []:
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                unique.append(text)
    lines.extend(
        [
            "",
            "### Aggregate trusted-component vocabulary",
            "",
            "Union of registry `trusted_components` strings (deduplicated, order of first appearance):",
            "",
        ]
    )
    for item in unique:
        lines.append(f"- {item}")
    if not unique:
        lines.append("- _(empty)_")

    lines.extend(
        [
            "",
            "## Kernel control-plane trust assumptions",
            "",
            "Beyond per-adapter tools, an independent reviewer should treat these as in-TCB for "
            "strict-mode decisions:",
            "",
            "- Decision lattice aggregation (`ovk.core.decision`) and exit-code mapping",
            "- Evidence integrity envelope / digests (`ovk.core.evidence_integrity`)",
            "- Capability + conformance honesty gates (`release_status=stable` requires full suite)",
            "- Trusted policy / metadata provenance loading for self-protection and deployment lanes",
            "- FormalPR-Bench version manifest digests when citing benchmark scores",
            "",
            "## Out of TCB (explicit non-claims)",
            "",
            "- Unavailable optional native binaries (must not promote to allow in strict mode)",
            "- Floating `@main` Action pins or unverified PyPI builds without matching tag evidence",
            "- Human pilot ledgers and advisory pilot fixture metrics (evidence for adoption, not TCB)",
            "- Re-attributing signed `v1.2.1` Sigstore evidence to this RC source tree",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_full_document(repo_root: Path) -> str:
    body = render_tcb_body(repo_root)
    return (
        "# Trusted Computing Base\n"
        "\n"
        "Independent-reviewer TCB inventory for Open Verification Kernel (OVK-PR9).\n"
        "Derived from the normative capability registry (`trusted_components`), "
        "composite Action release pins, and the private GitHub App alpha surface.\n"
        "\n"
        f"{BEGIN}\n"
        f"{body}"
        f"{END}\n"
    )


def _replace_marked_section(text: str, begin: str, end: str, body: str) -> str:
    if begin not in text or end not in text:
        raise ValueError(f"missing markers {begin!r} / {end!r}")
    before, rest = text.split(begin, 1)
    _old, after = rest.split(end, 1)
    return f"{before}{begin}\n{body}{end}{after}"


def expected_document(repo_root: Path) -> str:
    path = repo_root / "docs" / "TRUSTED_COMPUTING_BASE.md"
    body = render_tcb_body(repo_root)
    if path.exists():
        current = path.read_text(encoding="utf-8")
        if BEGIN in current and END in current:
            return _replace_marked_section(current, BEGIN, END, body)
    return render_full_document(repo_root)


def tcb_doc_stale(*, repo_root: Path | None = None) -> list[str]:
    """Return failure messages when TRUSTED_COMPUTING_BASE.md is missing or stale."""
    root = (repo_root or ROOT).resolve()
    path = root / "docs" / "TRUSTED_COMPUTING_BASE.md"
    if not path.exists():
        return ["missing docs/TRUSTED_COMPUTING_BASE.md"]
    current = path.read_text(encoding="utf-8")
    if current != expected_document(root):
        return ["TCB document is stale; run python scripts/render_tcb_doc.py --write"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--write", action="store_true", help="Write docs/TRUSTED_COMPUTING_BASE.md")
    parser.add_argument("--check", action="store_true", help="Fail if the generated doc is stale")
    args = parser.parse_args()
    if not args.check and not args.write:
        args.write = True

    repo_root = args.repo_root.resolve()
    path = repo_root / "docs" / "TRUSTED_COMPUTING_BASE.md"
    expected = expected_document(repo_root)
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    stale = current != expected

    if args.write and stale:
        path.write_text(expected, encoding="utf-8")
        print(f"updated {path}")
    elif stale:
        print(f"stale: {path}", file=sys.stderr)
    else:
        print(f"up to date: {path}")

    if args.check and stale:
        print("TCB doc is stale; run: python scripts/render_tcb_doc.py --write", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
