# RTK sealed evaluation

This directory defines the methods-only freeze for a sealed evaluation of evidence applicability across verifier and context changes.

No benchmark outcomes, oracle labels, RTK predictions, or post-hoc metric choices belong in the protocol commit. Development adversarial cases used to modify RTK or adjacent verification code are excluded from the sealed test set.

Evaluation phases:

1. Freeze protocol, schemas, analysis plan, implementation identities, and transition eligibility rules.
2. Construct the historical transition census from the declared repositories.
3. Derive eligible cases deterministically from the census.
4. Produce oracle labels independently of RTK outputs.
5. Seal all case material and hashes.
6. Run the frozen RTK implementation once against the sealed set.
7. Analyze only the predeclared metrics and any clearly labeled exploratory analyses.

The branch containing this directory is staging only until the canonical experiment repository is writable.
