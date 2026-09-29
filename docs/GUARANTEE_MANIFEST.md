# Governed Guarantee Manifest

Durable guarantees live in the repository at:

    .verification/guarantees.json

The schema version is:

    ovk.guarantee_manifest.v1

The manifest is repository policy, not ordinary application input.

## Trust rule

For pull-request evaluation, OVK always loads the active guarantee set from the
exact base revision. The workspace/head file is loaded separately as a proposal.

    trusted base manifest  --->  assurance target for this PR
             |
             +---- compare ----> proposed head manifest
                                      |
                                      +---- Guarantee Diff / review

A pull request therefore cannot delete or redefine a guarantee and then evaluate
itself under the altered definition. Proposed manifest edits only become active
once they are incorporated into the trusted base of a later revision.

When no base SHA exists, such as an explicit local invocation, the workspace
manifest is the active target.

## Changed-files metadata is not the trust boundary

Whenever a base SHA is available, OVK reads the base manifest directly and
compares its canonical content with the workspace manifest.

The changed-files list is only a consistency signal. If base and head manifests
differ while change metadata does not report .verification/guarantees.json, OVK
records change_detection_mismatch.

If the base revision cannot be read, OVK does not substitute an empty manifest.
The assurance target becomes unavailable and callers must fail closed.

A genuinely absent manifest in an accessible base revision is distinct from an
unavailable base. It represents an empty trusted guarantee set and supports a
governed bootstrap pull request.

## Guarantee Diff

The semantic diff reports:

- added guarantee IDs;
- removed guarantee IDs;
- unchanged guarantee IDs;
- modified guarantees with exact changed fields.

Modified definitions distinguish machine-claim changes, statement changes,
assumption changes, dependency changes, origin-intent metadata changes, and
explicit specification-version changes.

A machine-claim change means the typed guarantee family or selector changed.
The natural-language statement remains display metadata.

These are descriptive differences. The diff does not classify a modification as
stronger or weaker because that would require an implication argument over the
old and new guarantee semantics.

## Example manifest

    {
      "schema_version": "ovk.guarantee_manifest.v1",
      "guarantees": [
        {
          "guarantee_id": "G-TENANT-AGENT-READ",
          "spec_version": "1",
          "guarantee_type": "protected_effect_integrity_v1",
          "statement": "Agent disclosure is authorized for the acted workspace.",
          "selector": {
            "effect_name": "workspace.agent.read",
            "resource_type": "Agent"
          },
          "assumptions": [],
          "dependencies": [],
          "origin_intent": {
            "owner": "security"
          }
        }
      ]
    }

The statement is not interpreted as a theorem. The machine claim is the typed
guarantee family plus selector defined by the Guarantee Graph.
