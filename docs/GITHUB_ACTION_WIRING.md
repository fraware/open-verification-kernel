# GitHub Action Wiring

The repository currently includes an Action scaffold. The intended v0 Action should call the OVK CLI or a small runner script once repository-diff inference is complete.

## Recommended Action behavior

- advisory mode should render evidence without failing the workflow;
- enforce mode should fail only when OVK returns a block recommendation;
- unknown-like results should produce human-review status;
- evidence should be uploaded as a workflow artifact;
- Markdown should be posted as a PR comment by a later GitHub integration step.

## Minimal shell flow

```bash
python -m pip install --upgrade pip
pip install -e '.[dev]'
ovk init
ovk demo-self-protection examples/no_agent_self_approval/input_gate_preserved.json --output ovk-evidence.json --markdown-output ovk-pr-comment.md --repo "$GITHUB_REPOSITORY" --head-sha "$GITHUB_SHA" --no-enforce
```

For an intentionally failing demo, replace the input with:

```text
examples/no_agent_self_approval/input_gate_removed.json
```

## Production flow

The production Action should not rely on demo fixtures. It should:

1. collect changed files from the PR;
2. build structured input for detected intents;
3. run the selected adapters;
4. emit `ovk-evidence.json`;
5. emit `ovk-pr-comment.md`;
6. upload both files as artifacts;
7. fail the job only for a block recommendation in enforce mode.
