# Label-Separated Holdout Evaluation

FormalPR-Holdout uses two separate GitHub Actions workflows so protected labels cannot influence candidate prediction generation. The release authorizer later binds both workflow artifacts to one exact candidate SHA.

## Required flow

1. **Predict without labels** using `.github/workflows/holdout-predict.yml` on the exact candidate/tag ref.
2. **Digest and manifest** the label-free prediction file. `scripts/digest_holdout_predictions.py` rejects embedded label/ground-truth fields and emits a manifest containing the candidate SHA and exact prediction-file SHA-256.
3. **Record the prediction workflow run ID.** The evaluation job must name the exact prior run that produced the artifact; artifact name alone is not sufficient provenance.
4. **Evaluate separately** with `.github/workflows/holdout-eval.yml`. Before any protected label access, it downloads the prediction artifact from that explicit run ID and verifies candidate identity plus the prediction SHA-256 against the manifest.
5. **Acquire the frozen holdout asset** using the protected credential only in the download step and verify its immutable SHA-256.
6. **Strip credentials**, run evaluation in a token-free environment, and publish aggregate metrics only (`formalpr_holdout.aggregate_metrics.v1`).
7. **Authorize later.** Ordinary prediction/evaluation artifacts record candidate provenance but never mint `verified_source_sha`; only the complete release-ledger authorizer may do that.

## Binding chain

The public aggregate evidence must establish:

```text
candidate_source_sha
  -> exact prediction workflow run ID
  -> holdout-predictions.json SHA-256
  -> holdout-prediction-manifest.json binding
  -> frozen holdout release tag + asset SHA-256
  -> holdout-aggregate-metrics.json SHA-256
```

A missing run ID, artifact, manifest, digest, candidate match, or frozen-asset digest is a hard failure. The evaluator must not fall back to a similarly named artifact from another run.

## In-repo surfaces

| Item | Path / note |
|---|---|
| Label-free prediction workflow | `.github/workflows/holdout-predict.yml` |
| Label-separated evaluation workflow | `.github/workflows/holdout-eval.yml` |
| Prediction builder/digest guard | `scripts/digest_holdout_predictions.py` |
| Holdout runner | `scripts/run_formalpr_holdout.py` (requires immutable `--asset-sha256`) |
| Live artifact authorizer | `scripts/verify_release_ledger_github.py` |
| Aggregate schema | `schemas/holdout.aggregate_metrics.schema.json` |
| Governance | [FORMALPR_HOLDOUT_GOVERNANCE.md](FORMALPR_HOLDOUT_GOVERNANCE.md) |
| Release procedure | [RELEASE.md](RELEASE.md) |
| Public benchmark partitions | [BENCHMARK.md](BENCHMARK.md) |

Protected labels must never be committed to this repository. Prediction artifacts must remain label-free. Aggregate artifacts must not emit protected case IDs, labels, expected outcomes, or adjudication details.

## Contamination boundary

FormalPR-Bench and FormalPR-Holdout are distinct evidence systems. Template-development cases listed in `benchmarks/formal_pr_bench/template_dev_cases.json` cannot be counted as FormalPR-Bench `held_out` evaluation. Protected FormalPR-Holdout cases/labels cannot be copied into FormalPR-Bench, examples, tests, templates, public issues, or ordinary CI logs.

## Release checklist

- [ ] prediction workflow runs on the exact release candidate/tag without holdout label credentials;
- [ ] prediction JSON passes the label-free guard;
- [ ] prediction manifest records exact candidate SHA and prediction SHA-256;
- [ ] exact prediction workflow run ID is retained;
- [ ] evaluation workflow explicitly consumes that run ID;
- [ ] evaluation verifies candidate and prediction digest before protected-label access;
- [ ] frozen holdout release tag and `HOLDOUT_ASSET_SHA256` are verified;
- [ ] download credentials are removed before evaluation;
- [ ] aggregate schema validates and exposes aggregates only;
- [ ] aggregate binds prediction digest and holdout asset digest;
- [ ] prediction/eval artifacts contain no `verified_source_sha` authority claim;
- [ ] the release ledger independently re-downloads and verifies both artifacts before authorization.

## External dependency

The protected label store and annotator process live in the private `fraware/FormalPR-Holdout` repository. This repository can enforce the separation/provenance protocol but cannot truthfully claim a live governed holdout evaluation has occurred until the protected workflow actually runs and its exact artifacts are retained.