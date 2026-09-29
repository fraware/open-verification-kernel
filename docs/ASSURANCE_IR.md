# Assurance IR v1

Assurance IR is OVK's typed semantic interchange layer between repository/source
extraction and verification-obligation compilation.

    repository change
          |
          v
    source/profile extractor
          |
          v
    Assurance IR
          |
          v
    verification obligations
          |
          v
    backend evidence
          |
          v
    OVK decision

The IR is descriptive, not evidentiary. A valid Assurance IR object says that an
extractor produced a well-formed semantic model for a specific repository
revision. It does not prove that the source program has the modeled behavior.

## Initial vocabulary

The v1 model includes principals, resources, namespaced effects, path conditions,
authorization guards, protected effects, resource bindings, semantic paths,
assurance claims, abstraction coverage, assumptions, and source provenance.

Effects are open namespaced strings rather than a closed enum. This lets
application profiles introduce domain semantics such as billing.invoice.refund
without modifying OVK core.

## Identity

AssuranceIR.assurance_ir_digest uses OVK canonical JSON hashing after sorting
collections that are semantically set-like. The digest binds the semantic model
while avoiding identity changes caused only by collection ordering.

The digest is suitable for evidence and provenance binding. It does not establish
source-to-IR soundness.

## Trust boundary

There are two independent questions:

1. Extraction: does the Assurance IR faithfully model the relevant source behavior?
2. Verification: does the selected backend establish the claim over that IR?

A machine-checked proof of a claim over an incorrect abstraction does not prove
the corresponding property of the source program. Extractors must record
coverage, unsupported constructs, assumptions, identity, and source provenance.

## Non-goals for v1

This module does not change OVK merge decisions, define protected-effect proof
semantics, claim source-profile soundness, add a verification backend, or replace
existing VerificationIntent and VerificationObligation objects.
