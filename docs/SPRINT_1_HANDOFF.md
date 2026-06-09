# Sprint 1 Handoff

Sprint 1 is closed. It makes the self-protection path honest and usable as the first PR-style runner.

## Implemented

- `docs/STATUS_ANALYSIS.md` records the repository status, sprint plan, Sprint 1 closure, and next sprint priorities.
- `ovk.adapters.opa.self_protection` returns `unknown` for high-risk AI-agent workflow changes when required-check metadata is missing.
- Concrete self-protection failures still take precedence over unknown metadata.
- `ovk.core.self_protection_input` normalizes metadata into canonical adapter input.
- `ovk.core.changed_files` ingests changed files from JSON, newline text, or unified diff.
- `ovk.core.check_metadata` normalizes explicit before/after required-check metadata.
- `ovk.core.sprint1_runner` composes metadata, changed files, check metadata, adapter evaluation, evidence bundle, Markdown, and attestation.
- `scripts/run_v0_self_protection.py` calls the Sprint 1 runner.
- `ovk ci` runs the Sprint 1 self-protection path.
- `action.yml` calls `ovk ci` in advisory or strict mode.
- CI exercises `ovk ci` and uploads evidence, Markdown, and attestation artifacts.
- Fixtures cover removed gate, missing metadata, changed files, and required-check metadata.
- Tests cover fail, pass, unknown, config-change failure, metadata normalization, changed-file ingestion, runner outputs, and artifact writing.
- The seed benchmark includes a missing-metadata case.

## Current commands

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

Composable CI-style command:

```bash
ovk ci \
  --metadata examples/no_agent_self_approval/metadata_missing_required_checks.json \
  --changed-files examples/no_agent_self_approval/changed_files_workflow.txt \
  --evidence-output ovk-evidence.json \
  --markdown-output ovk-pr-comment.md \
  --attestation-output ovk-attestation.json \
  --repo example/repo \
  --head-sha demo-head \
  --advisory
```

With explicit required-check metadata:

```bash
ovk ci \
  --metadata examples/no_agent_self_approval/metadata_missing_required_checks.json \
  --changed-files examples/no_agent_self_approval/changed_files_workflow.txt \
  --check-metadata examples/no_agent_self_approval/check_metadata_gate_removed.json \
  --repo example/repo \
  --head-sha demo-head
```

Expected outcomes:

- removed gate returns `block`;
- missing metadata returns `require_human_review`;
- advisory mode writes outputs and exits 0;
- strict mode returns a nonzero exit code for `block` or `require_human_review`.

## Remaining caveat

Sprint 1 accepts explicit required-check metadata and treats missing metadata as unknown. It does not yet query GitHub branch-protection settings directly. That belongs to Sprint 2.

## Engineering rule

A high-risk AI-agent workflow or verification-control change must never receive an `allow` recommendation when required-check metadata is unavailable.
