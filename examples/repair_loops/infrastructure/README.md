# Infrastructure repair loop

Reproducible failing and passing diffs for the `restrict_public_access` repair class.

```bash
ovk check --changed-files examples/repair_loops/infrastructure/failing.diff --repo example/repo --head-sha seed
ovk repair-suggest --evidence ovk-evidence.json
ovk check --changed-files examples/repair_loops/infrastructure/passing.diff --repo example/repo --head-sha repaired
```

Or run the end-to-end demo:

```bash
python examples/repair_loops/infrastructure/demo_repair_loop.py
```
