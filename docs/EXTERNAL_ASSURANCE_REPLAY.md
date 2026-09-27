# External Assurance Replay

External replay extends the durable-assurance product qualification harness to
pinned public repositories without copying upstream source into the OVK
benchmark tree.

It is deliberately separate from the default internal qualification workflow.
Network availability must not affect the deterministic internal benchmark.

## Evidence model

An external replay case binds:

- repository identity;
- HTTPS GitHub repository URL;
- full 40-character base and head commit SHAs;
- a safe/unsafe label;
- expected head assurance state;
- typed durable guarantee manifest;
- typed Protected Effect extraction profile;
- public or qualification-review provenance.

The runner fetches those immutable revisions, selects only files matched by the
trusted source profile, and computes content digests for the selected base and
head materials before scoring them.

Upstream application code is never imported or executed by the replay runner.

## Replay path

The external source transition is converted into the same qualification case
type used by the internal product benchmark:

    pinned external Git revisions
        -> selected source materials
        -> content digests
        -> isolated replay repository
        -> ordinary run_check
        -> Code Diff + Guarantee Diff + Assurance Diff
        -> common qualification metrics

This keeps external and internal results comparable.

## Human adjudication

Public advisories, merged fixes, and public issue labels are useful provenance,
but they do not count as qualification human adjudications.

Only:

    qualification_human_adjudicated = true

contributes to the human-adjudicated PR depth used by the production
qualification gate.

If review time is recorded, human_review_minutes is accepted only for a
qualification-human-adjudicated case. The runner never estimates human minutes
from an automated outcome.

## Repository URL restriction

Production external replay accepts HTTPS GitHub repository URLs whose path
matches the declared owner/repository identity.

Local file:// URLs exist only as an explicit test-only option in the Python API;
the command-line runner does not enable them.

## Example

    {
      "schema_version": "ovk.assurance_external_replay_suite.v1",
      "suite_id": "external-fastapi-security-v1",
      "cases": [
        {
          "case_id": "upstream-security-fix",
          "repository": "owner/repository",
          "repository_url": "https://github.com/owner/repository.git",
          "base_sha": "<40-char vulnerable commit>",
          "head_sha": "<40-char fixed commit>",
          "safety_label": "safe",
          "expected_head_assurance": "established",
          "guarantee_manifest": {},
          "protected_effect_profile": {},
          "provenance": {
            "adjudication_kind": "public_security_advisory",
            "references": [
              "https://github.com/advisories/..."
            ]
          },
          "qualification_human_adjudicated": false,
          "human_review_minutes": null
        }
      ]
    }

Run:

    python scripts/run_external_assurance_replay.py path/to/suite.json

The resulting report records the pinned revisions, upstream material digests,
selected paths, and the ordinary product-qualification result for each case.

## Qualification interpretation

A successful public replay is independent external technical evidence only when
the case was not used to tune the implementation.

It still does not satisfy the production gate by itself. The current gate also
requires at least two independent external repositories and thirty
qualification-human-adjudicated PRs per repository.
