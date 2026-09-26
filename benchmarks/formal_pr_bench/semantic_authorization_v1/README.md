# Semantic Authorization v1 development cases

This directory contains public, provenance-grounded development cases for
Protected Effect Integrity and resource/scope binding.

These cases are not held out. Public advisories may occur in model training
corpora, so success on them does not measure model novelty or contamination-free
generalization.

The cases are intentionally reduced. They preserve the security-relevant
semantic structure while avoiding dependence on an upstream repository's exact
implementation.

Current case families:

- cross-workspace resource lookup;
- authorization scope versus acted-resource scope.

Protected holdout cases should be generated separately from fresh mutations or
private prospective data with labels isolated from implementation work.
