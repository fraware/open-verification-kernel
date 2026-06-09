# Sprint 2 Status

Sprint 2 focuses on replacing manual metadata assumptions with stronger GitHub metadata ingestion and preparing the OPA-backed self-protection path.

## Completed so far

- Added `ovk.core.github_event` to parse GitHub Actions event payloads.
- Added event fixture `examples/github_events/pull_request_bot.json`.
- Extended `ovk.core.check_metadata` to normalize GitHub branch-protection-shaped required-check metadata.
- Added fixture `examples/no_agent_self_approval/check_metadata_github_shape_removed.json`.
- Extended `ovk.core.sprint1_runner` to accept GitHub event metadata.
- Extended `ovk ci` with `--github-event`.
- Updated `action.yml` to pass `github.event_path` into `ovk ci`.
- Updated CI to exercise the GitHub event metadata path.
- Added conservative GitHub API metadata collector in `ovk.core.github_api_metadata`.
- Added required-check metadata normalization script at `scripts/normalize_required_checks.py`.
- Added OPA self-protection policy asset generation in `ovk.adapters.opa.policy_assets`.
- Added materialized Rego fixture at `adapters/opa/policies/self_protection.rego`.
- Added optional OPA CLI runner in `ovk.adapters.opa.optional_runner`.
- Added OPA raw-result normalization into `VerificationEvidence` in `ovk.adapters.opa.evidence`.
- Added optional OPA integration tests that skip when the OPA binary is unavailable.
- Added opt-in PR comment posting script at `scripts/post_pr_comment.py`.
- Updated `action.yml` with `post-comment: "true"` support.
- Added installation guide at `docs/INSTALLATION.md`.
- Added tests for GitHub event metadata, GitHub-shaped required-check metadata, GitHub API metadata helpers, OPA policy assets, optional OPA runner behavior, OPA evidence normalization, helper scripts, and optional OPA integration.

## Current command

```bash
ovk ci \
  --github-event examples/github_events/pull_request_bot.json \
  --metadata examples/no_agent_self_approval/metadata_missing_required_checks.json \
  --changed-files examples/no_agent_self_approval/changed_files_workflow.txt \
  --check-metadata examples/no_agent_self_approval/check_metadata_github_shape_removed.json \
  --evidence-output ovk-evidence.json \
  --markdown-output ovk-pr-comment.md \
  --attestation-output ovk-attestation.json \
  --advisory
```

## Remaining Sprint 2 work

1. Wire live GitHub branch-protection metadata collection directly into the Action when token permissions allow it.
2. Decide whether strict mode should use deterministic evaluator, OPA CLI, or both.
3. Add update-in-place behavior for PR comments so OVK does not create duplicate comments.
4. Add a real external-repository smoke test workflow once an integration repo exists.

## Engineering rule

The deterministic evaluator remains the fixture oracle. The OPA CLI path may strengthen evidence, but it must never weaken unknown/error semantics. Missing OPA binary, invalid OPA output, or timeout must return `unknown` or `error`, never `pass`.
