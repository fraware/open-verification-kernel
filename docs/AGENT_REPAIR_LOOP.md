# Agent Repair Loop

End-to-end flow for an MCP-connected agent that runs OVK on a pull request, receives a block with repair hints, patches the change, and reruns until green.

## Prerequisites

```bash
pip install -e '.[dev]'
ovk init
```

Optional: run the MCP server (`ovk-mcp` or `python -m ovk.mcp_stdio`) so your agent can call `ovk_check`, `ovk_repair_suggest`, and `ovk_generate_test`.

## CI secrets lane walkthrough

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
ovk repair-suggest ovk-evidence.json
```

Expected hint:

```json
{
  "fix_class": "remove_untrusted_secret_usage",
  "suggested_action": "Remove secret references from untrusted workflow triggers."
}
```

MCP equivalent: call the repair-suggest tool with the evidence bundle path.

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

## FormalPR-Bench repair_loop category

Extended benchmark cases score:

1. Initial diff blocks (or requires review) with a useful repair hint class
2. Optional `passing_fixture` reruns green after repair

Run locally:

```bash
ovk bench --expanded
```

Repair-loop cases include ci_secrets, auth bypass, infra exposure, and deployment skip lanes.

## MCP session sketch

1. Agent opens PR with a workflow diff.
2. Agent calls `ovk check` (or GitHub Action runs in strict mode).
3. On block, agent calls `ovk repair-suggest` and reads `fix_class`.
4. Agent patches the workflow file.
5. Agent reruns `ovk check` until recommendation is `allow`.
6. Agent optionally commits generated regression tests from `ovk generate-test`.

See [SYSTEM_SPEC.md](SYSTEM_SPEC.md) step 10 for the north-star behavior this demonstrates.
