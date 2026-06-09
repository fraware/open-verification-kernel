# Sprint 4 Current State

Sprint 4 has turned the infrastructure exposure path into a usable v0 verification lane.

## Implemented

- Native infrastructure input schema.
- Infrastructure resource model.
- Input validation.
- Exposure checker.
- Evidence construction.
- Public and private resource fixtures.
- Runner script.
- First-class `ovk infra-exposure` command for native infrastructure input.
- Benchmark scorer protected through pytest.
- Terraform-plan-style normalization hook.
- Kubernetes-style normalization hook.
- Unified input normalizer for native, Terraform-style, and Kubernetes-style input.
- Multi-format standalone runner support.
- Regression artifact rendering.
- Regression artifact writer.
- Configurable exposure policy object.
- Policy JSON loader.
- Policy schema.
- Policy contract documentation.
- Graph-style normalization hook.

## Current semantics

- Public exposure of resources whose sensitivity is blocked by policy returns `block`.
- Private sensitive resources return `allow`.
- Invalid infrastructure abstractions return `require_human_review`.
- Unsupported or empty normalization results are treated as invalid input.
- Concrete counterexamples generate regression artifacts.

## Current command surface

- `ovk infra-exposure` supports native OVK infrastructure input.
- `scripts/run_infra_exposure.py` supports native, Terraform-style, and Kubernetes-style input through `--input-format`.
- `scripts/write_infra_regression.py` materializes generated regression artifacts from evidence bundles.

## Current limitations

- The first-class `ovk infra-exposure` command does not yet support `--input-format` because the CLI patch was blocked.
- The graph hook is not yet wired into the unified normalizer because the patch was blocked.
- The graph schema write was blocked.
- Full Terraform and Kubernetes parsing remain out of scope for v0; current hooks intentionally support narrow normalized subsets.

## Next sprint direction

Sprint 5 should focus on release hardening: attestation envelopes, artifact layout, installation polish, example repository workflows, and v0.1 readiness.
