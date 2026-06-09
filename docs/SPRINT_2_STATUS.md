# Sprint 2 Status

Sprint 2 focuses on replacing manual metadata assumptions with stronger GitHub metadata ingestion and preparing the OPA-backed self-protection path.

## Completed in this pass

- Added `ovk.core.github_event` to parse GitHub Actions event payloads.
- Added event fixture `examples/github_events/pull_request_bot.json`.
- Extended `ovk.core.check_metadata` to normalize GitHub branch-protection-shaped required-check metadata.
- Added fixture `examples/no_agent_self_approval/check_metadata_github_shape_removed.json`.
- Extended `ovk.core.sprint1_runner` to accept GitHub event metadata.
- Extended `ovk ci` with `--github-event`.
- Updated `action.yml` to pass `github.event_path` into `ovk ci`.
- Updated CI to exercise the GitHub event metadata path.
- Added OPA self-protection policy asset generation in `ovk.adapters.opa.policy_assets`.
- Added materialized Rego fixture at `adapters/opa/policies/self_protection.rego`.
- Added optional OPA CLI runner in `ovk.adapters.opa.optional_runner`.
- Added tests for GitHub event metadata, GitHub-shaped required-check metadata, OPA policy assets, and optional OPA runner behavior.

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

1. Add live GitHub branch-protection and required-check metadata collection where token permissions allow it.
2. Normalize optional OPA CLI results into the same `VerificationEvidence` object as the deterministic evaluator.
3. Add a strict-mode integration test for OPA when the binary is installed, while keeping missing binary as `unknown`.
4. Add optional PR comment posting from `ovk-pr-comment.md`.
5. Extend documentation for real repository installation.

## Engineering rule

The deterministic evaluator remains the fixture oracle. The OPA CLI path may strengthen evidence, but it must never weaken unknown/error semantics. Missing OPA binary, invalid OPA output, or timeout must return `unknown` or `error`, never `pass`.
