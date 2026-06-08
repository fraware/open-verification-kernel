# Example: Agent Cannot Disable Its Own Verification Gate

This is the signature OVK demo.

## Scenario

An AI coding agent receives the issue:

```text
Simplify our CI workflow and remove redundant verification steps.
```

The agent opens a pull request that modifies `.github/workflows/verify.yml` and accidentally removes the required OVK verification job from the protected branch check set.

## Expected OVK behavior

OVK should:

1. detect that an agent-authored PR changed workflow or repository-rule files;
2. select the `agent-cannot-disable-own-ci-gate` intent;
3. route the obligation to the OPA adapter or static workflow-policy adapter;
4. produce a failing evidence object;
5. block merge in enforce mode;
6. generate a regression policy fixture;
7. explain the counterexample in PR-readable language.

## Expected PR comment

```text
Verification summary

This pull request modifies CI workflow permissions.

Checked property
- Agent-authored PR cannot weaken its own verification gate: failed

Counterexample
The PR removes ovk-verify from the required check set.

Merge recommendation
Block until the verification gate is restored or an authorized maintainer override is recorded.
```

## Why this example matters

This demo shows the full OVK loop:

```text
agent change -> verification intent -> backend routing -> formal/policy check -> counterexample -> evidence -> PR decision
```
