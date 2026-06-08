# First End-to-End Demo

This document explains the first OVK demo that engineers can run today.

## Goal

Show that OVK can evaluate the first production-relevant policy:

```text
An AI-authored pull request must preserve the verification controls that govern its own merge.
```

## Current implementation

The first adapter lives in:

```text
ovk/adapters/opa/self_protection.py
```

It implements OPA-style policy semantics with a deterministic Python evaluator so the demo and CI do not require a local OPA binary. A later hardening pass should wire the same policy shape to the OPA CLI.

## Failing demo

Run:

```bash
python scripts/run_self_protection_demo.py examples/no_agent_self_approval/input_gate_removed.json
```

Expected behavior:

- backend claim status: `fail`
- counterexample failure mode: `required_check_removed`
- merge recommendation: `block`
- process exit code: `1`

## Passing demo

Run:

```bash
python scripts/run_self_protection_demo.py examples/no_agent_self_approval/input_gate_preserved.json
```

Expected behavior:

- backend claim status: `pass`
- no counterexamples
- merge recommendation: `allow`
- process exit code: `0`

## Why the first demo matters

This proves the OVK loop in miniature:

```text
agent-authored change
→ verification intent
→ OPA-style policy evaluation
→ normalized evidence
→ merge recommendation
```

## Next hardening tasks

1. Add the real OPA CLI execution path.
2. Add policy fixtures under `adapters/opa/policies/`.
3. Replace the standalone demo script with `ovk run` and `ovk ci` commands.
4. Have the GitHub Action call `ovk ci` in enforce mode.
5. Generate a PR comment from the evidence object.
