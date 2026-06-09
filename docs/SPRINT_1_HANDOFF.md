# Sprint 1 Handoff

Sprint 1 focuses on making the self-protection path honest and usable as the first PR-style runner.

## Implemented in this pass

- `docs/STATUS_ANALYSIS.md` now records the repository status, sprint plan, Sprint 1 progress, and remaining Sprint 1 work.
- `ovk.adapters.opa.self_protection` now returns `unknown` for high-risk AI-agent workflow changes when required-check metadata is missing.
- Concrete self-protection failures still take precedence over unknown metadata.
- `ovk.core.self_protection_input` normalizes metadata into canonical adapter input.
- `scripts/run_v0_self_protection.py` emits:
  - evidence bundle JSON;
  - PR-ready Markdown;
  - unsigned in-toto-style attestation statement.
- New fixtures cover removed gate and missing metadata.
- New tests cover fail, pass, unknown, config-change failure, and metadata normalization.
- The seed benchmark now includes a missing-metadata case.

## Current runner commands

Removed gate case:

```bash
python scripts/run_v0_self_protection.py \
  examples/no_agent_self_approval/metadata_gate_removed.json \
  --repo example/repo \
  --head-sha demo-head
```

Missing metadata case:

```bash
python scripts/run_v0_self_protection.py \
  examples/no_agent_self_approval/metadata_missing_required_checks.json \
  --repo example/repo \
  --head-sha demo-head
```

Expected outcomes:

- removed gate returns `block`;
- missing metadata returns `require_human_review`;
- advisory mode writes outputs and exits 0.

## Remaining Sprint 1 work

1. Add changed-file ingestion from GitHub PR metadata or local `git diff`.
2. Add branch-protection and required-check metadata collection.
3. Add a single `ovk ci` command around the v0 self-protection runner.
4. Wire the GitHub Action to call `ovk ci`.
5. Upload evidence and Markdown artifacts in CI.

## Engineering rule

A high-risk AI-agent workflow or verification-control change must never receive an `allow` recommendation when required-check metadata is unavailable.
