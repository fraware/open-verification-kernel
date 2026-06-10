# Agent Repair Loop

End-to-end flow for an MCP-connected agent that runs OVK on a pull request, receives a block with repair hints, patches the change, and reruns until green.

## Prerequisites

```bash
pip install -e '.[dev]'
ovk init
```

Optional: run the MCP server (`ovk-mcp` or `python -m ovk.mcp_stdio`) for planning and verification tools (`ovk.plan_from_diff`, `ovk.run_verification`, `ovk.get_merge_recommendation`). Use the CLI for `ovk check`, `ovk repair-suggest`, and `ovk generate-test` in the repair loop today.

## Repair loops by check type

OVK ships reproducible repair-loop fixtures for four check types. Each includes `failing.diff`, `repair.patch`, `passing.diff`, and `demo_repair_loop.py`.

| Check type | Fixture directory | Expected `fix_class` |
|------|-------------------|----------------------|
| CI secrets | `examples/repair_loops/ci_secrets/` | `remove_untrusted_secret_usage` |
| Authorization | `examples/repair_loops/authorization/` | `add_route_guard` |
| Infrastructure | `examples/repair_loops/infrastructure/` | `restrict_public_access` |
| Deployment | `examples/deployment_state/input_skipped_approval.json` (focused CLI) or multi-surface diffs | `add_approval_transition` |

Run a demo:

```bash
python examples/repair_loops/authorization/demo_repair_loop.py
python examples/repair_loops/infrastructure/demo_repair_loop.py
python examples/repair_loops/ci_secrets/demo_repair_loop.py
```

## CI secrets check walkthrough

Use the reproducible fixtures in `examples/repair_loops/ci_secrets/`.

### Step 1 — Initial check blocks

```bash
ovk check \
  --changed-files examples/repair_loops/ci_secrets/failing.diff \
  --repo example/oss-repo \
  --head-sha agent-pr-1
```

Expected:

- `merge_recommendation`: `block`
- Counterexample failure mode: `secrets_exposed_in_untrusted_context`

### Step 2 — Read repair hints

```bash
ovk repair-suggest --evidence ovk-evidence.json
```

Expected hint:

```json
{
  "fix_class": "remove_untrusted_secret_usage",
  "suggested_action": "Remove secret references from untrusted workflow triggers."
}
```

MCP equivalent (today): run `ovk repair-suggest --evidence <path>` from the agent shell after `ovk.run_verification` or `ovk check` produces a bundle.

### Step 3 — Apply the fix and rerun

Apply `examples/repair_loops/ci_secrets/passing.diff` (or edit the workflow to remove `${{ secrets.* }}` from `pull_request` triggers).

```bash
ovk check \
  --changed-files examples/repair_loops/ci_secrets/passing.diff \
  --repo example/oss-repo \
  --head-sha agent-pr-2
```

Expected: `merge_recommendation`: `allow`

### Step 4 — Optional regression artifact

```bash
ovk generate-test --evidence ovk-evidence.json
```

Writes minimized counterexample fixtures under `.verification/generated_tests/`.

## Authorization check walkthrough

```bash
ovk check \
  --changed-files examples/repair_loops/authorization/failing.diff \
  --repo example/oss-repo \
  --head-sha agent-pr-1

ovk repair-suggest --evidence ovk-evidence.json

ovk check \
  --changed-files examples/repair_loops/authorization/passing.diff \
  --repo example/oss-repo \
  --head-sha agent-pr-2
```

Expected: initial block with `admin_route_reachable_by_non_admin`, repair hint `add_route_guard`, repaired allow.

## Infrastructure check walkthrough

```bash
ovk check \
  --changed-files examples/repair_loops/infrastructure/failing.diff \
  --repo example/oss-repo \
  --head-sha agent-pr-1

ovk repair-suggest --evidence ovk-evidence.json

ovk check \
  --changed-files examples/repair_loops/infrastructure/passing.diff \
  --repo example/oss-repo \
  --head-sha agent-pr-2
```

Expected: initial block with `sensitive_resource_publicly_exposed`, repair hint `restrict_public_access`, repaired allow.

## FormalPR-Bench repair_loop category

Extended benchmark cases score:

1. Initial diff blocks (or requires review) with a useful repair hint class
2. Optional `passing_fixture` reruns green after repair

Run locally:

```bash
ovk bench --expanded
```

Repair-loop cases cover ci_secrets, authorization, infrastructure, and deployment checks. Auth and infra cases use `examples/repair_loops/` fixtures sourced from `benchmarks/real_diffs/`.

## MCP session sketch

1. Agent opens PR with a workflow diff.
2. Agent calls `ovk check` (or GitHub Action runs in strict mode).
3. On block, agent calls `ovk repair-suggest` and reads `fix_class`, `lane`, and `affected_file` when present.
4. Agent patches the workflow file.
5. Agent reruns `ovk check` until recommendation is `allow`.
6. Agent optionally commits generated regression tests from `ovk generate-test`.

See [SYSTEM_SPEC.md](SYSTEM_SPEC.md) step 10 for the end-to-end behavior this demonstrates.
