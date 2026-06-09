# Sprint 4 Status

Sprint 4 starts the infrastructure exposure path.

## Goal

Add a conservative checker for public exposure of sensitive infrastructure resources.

## Completed so far

- Added `schemas/infrastructure.input.schema.json`.
- Added `ovk.adapters.infra.model`.
- Added `ovk.adapters.infra.validation`.
- Added `ovk.adapters.infra.exposure`.
- Added `ovk.adapters.infra.evidence`.
- Added public and private infrastructure exposure fixtures.
- Added schema tests, validation tests, exposure tests, and evidence tests.

## Current semantics

- Public exposure of confidential or restricted resources returns `fail` and `block`.
- Private sensitive resources return `pass` and `allow`.
- Invalid infrastructure abstractions return `unknown` and `require_human_review`.

## Current limitation

The checker consumes a supplied infrastructure abstraction. It does not yet parse Terraform, Kubernetes, IAM, or cloud-provider configuration files directly.

## Remaining Sprint 4 work

1. Add an infrastructure exposure runner that emits evidence, Markdown, and attestation.
2. Add a first-class CLI command.
3. Add benchmark scoring for infrastructure exposure cases.
4. Add more resource kinds and exposure path cases.
5. Add parser hooks for Terraform or Kubernetes abstractions.

## Engineering rule

Invalid infrastructure abstractions must never produce `allow`. Missing or malformed exposure metadata requires human review.
