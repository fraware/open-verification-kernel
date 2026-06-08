# v0 Runner Design

The v0 runner should compose the modules already present in the repository.

## Current modules

- `ovk.core.diff_parser` extracts changed paths from unified diff text.
- `ovk.core.change_detection` maps changed paths to engineering surfaces.
- `ovk.core.intent_registry` loads verification intent templates.
- `ovk.core.capabilities` loads backend capability manifests.
- `ovk.core.router` chooses candidate backends for an intent.
- `ovk.adapters.opa.self_protection` evaluates the first CI self-protection check.
- `ovk.adapters.z3.authorization` evaluates the first authorization reachability check.
- `ovk.core.bundle` builds content-addressed evidence bundles.
- `ovk.core.render` renders PR-ready Markdown.
- `ovk.core.attestation` emits an unsigned in-toto-style statement.

## Intended runner flow

1. Read changed files from GitHub metadata or a unified diff.
2. Detect changed engineering surfaces.
3. Infer candidate intent IDs.
4. Load intent templates.
5. Load capability manifests.
6. Route each intent to candidate backends.
7. Execute only adapters with sufficient structured input.
8. Mark missing structured input as an open obligation.
9. Build a content-addressed evidence bundle.
10. Render Markdown for the PR.
11. Emit an unsigned attestation statement.

## Conservative rule

If a high-risk candidate intent is detected but no adapter input can be built, the runner should return `require_human_review`, never `allow`.

## First implementation target

The first production runner should support:

- changed GitHub Actions workflow files;
- `.verification/` file changes;
- self-protection intent selection;
- self-protection structured input construction;
- evidence bundle generation;
- Markdown rendering;
- non-zero CI exit on a block recommendation.

## Second implementation target

The second runner should support:

- changed route and middleware files;
- authorization intent selection;
- route reachability abstraction;
- optional Z3-backed encoding;
- regression test generation from counterexamples.
