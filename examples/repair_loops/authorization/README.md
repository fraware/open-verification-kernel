# Authorization repair loop

Reproducible failing and passing diffs for the `add_route_guard` repair class.

```bash
ovk check --changed-files examples/repair_loops/authorization/failing.diff --repo example/repo --head-sha seed
ovk repair-suggest ovk-evidence.json
ovk check --changed-files examples/repair_loops/authorization/passing.diff --repo example/repo --head-sha repaired
```

Or run the end-to-end demo:

```bash
python examples/repair_loops/authorization/demo_repair_loop.py
```
