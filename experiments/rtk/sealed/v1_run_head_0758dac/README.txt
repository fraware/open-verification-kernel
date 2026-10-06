RTK v1 authentic module handoff
================================

This bundle contains the exact five repository files checked out by GitHub Actions run 37420715584 at commit:
0758dac59230cb8110c07c1cd6e5fc2e4bc11317

It is a provenance handoff, not the jsonschema-fixed workflow. The authentic workflow in this bundle still reproduces the historical failure boundary: the validation step imports jsonschema without installing it.

Before using any file:

  python VERIFY.py

All five files must report OK. PROVENANCE.json contains the workflow/run/job identity, frozen inputs, byte sizes, SHA-256 digests, and Git blob SHA-1 identities.

For the v1 repair, first preserve these bytes as the historical baseline. Then make the narrow environment-only dependency repair in a new commit, rerun the complete workflow at one exact SHA, and bind outputs only from a fully successful run.

Do not describe the repaired workflow as byte-identical to this handoff.
