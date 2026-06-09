# Installing Open Verification Kernel in a Repository

This guide describes the current v0 integration path. The Action is usable, but still early. It focuses on the self-protection check for AI-agent changes to workflow and verification-control files.

## Minimal advisory setup

Add a workflow such as:

```yaml
name: OVK

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  ovk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fraware/open-verification-kernel@main
        with:
          mode: advisory
          post-comment: "true"
```

Advisory mode writes evidence and returns success. It is appropriate for first installation.

## Strict setup

Strict mode returns a nonzero exit code when OVK recommends `block` or `require_human_review`.

```yaml
- uses: fraware/open-verification-kernel@main
  with:
    mode: strict
    post-comment: "true"
```

Use strict mode only after confirming that required-check metadata is supplied or that `require_human_review` is the intended behavior for missing metadata.

## Required-check metadata

The current Action accepts required-check metadata through a file. If metadata is unavailable, OVK returns `require_human_review` for high-risk AI-agent workflow changes.

Example metadata:

```json
{
  "before_required_checks": ["unit-tests", "ovk-verify"],
  "after_required_checks": ["unit-tests", "ovk-verify"]
}
```

GitHub branch-protection-shaped JSON is also accepted:

```json
{
  "after_branch_protection": {
    "required_status_checks": {
      "contexts": ["unit-tests", "ovk-verify"]
    }
  }
}
```

Normalize such a file with:

```bash
python scripts/normalize_required_checks.py branch_protection.json --output ovk-required-checks.json
```

Then pass it to the Action:

```yaml
- uses: fraware/open-verification-kernel@main
  with:
    check-metadata: ovk-required-checks.json
```

## Outputs

The Action writes:

- `ovk-evidence.json`
- `ovk-pr-comment.md`
- `ovk-attestation.json`

A repository workflow can upload these as artifacts.

## PR comments

Set:

```yaml
post-comment: "true"
```

The Action will try to post `ovk-pr-comment.md` as a pull-request comment. If the event is not a pull request or the token is unavailable, the script exits successfully without posting.

## Current limitations

- The self-protection check is deterministic Python with a Rego policy fixture and optional OPA runner.
- Live branch-protection collection is implemented as library support, but the Action does not yet collect it automatically.
- PR comment posting is append-only and does not yet update an existing OVK comment.
- Missing required-check metadata returns `require_human_review`, by design.
