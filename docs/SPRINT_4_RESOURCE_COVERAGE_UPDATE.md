# Sprint 4 Resource Coverage Update

The infrastructure exposure checker now has broader resource coverage.

Implemented:

- Public confidential resources block.
- Public restricted resources block.
- Private confidential resources allow.
- Public resources may be public.
- Exposure-path details are preserved in counterexamples.

These cases reduce overfitting to the first object-storage fixture and clarify that sensitivity, not resource type alone, drives the exposure decision.
