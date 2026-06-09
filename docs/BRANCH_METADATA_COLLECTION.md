# Branch Metadata Collection

OVK can consume required-check metadata in three ways.

## 1. Explicit metadata file

The most reliable current method is to provide a JSON file directly.

```json
{
  "before_required_checks": ["unit-tests", "ovk-verify"],
  "after_required_checks": ["unit-tests", "ovk-verify"]
}
```

Pass it to OVK with:

```bash
ovk ci --check-metadata ovk-required-checks.json
```

## 2. GitHub-shaped metadata file

OVK also accepts branch-protection-shaped JSON.

```json
{
  "after_branch_protection": {
    "required_status_checks": {
      "contexts": ["unit-tests", "ovk-verify"]
    }
  }
}
```

Normalize it with:

```bash
python scripts/normalize_required_checks.py branch_protection.json --output ovk-required-checks.json
```

## 3. Conservative branch metadata collector

The repository includes:

```bash
python scripts/collect_branch_metadata.py --repository owner/repo --branch main --output ovk-required-checks.json
```

If branch metadata cannot be collected, the script writes an empty JSON object. OVK then treats required-check metadata as unavailable and returns `require_human_review` for high-risk agent-authored workflow changes.

## Current Action status

The composite Action supports explicit metadata through `check-metadata`. Direct Action wiring for live branch metadata collection is not enabled by default. This is intentional until token permissions and repository policy are configured deliberately.

## Safety rule

Failure to collect metadata must never produce an `allow` recommendation. Missing metadata remains an unknown state.
