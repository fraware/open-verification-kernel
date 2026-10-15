# Advisory guarantee continuity review — pilot v1

**Status:** research-dependent product demonstration, not production authorization. This branch is stacked on draft PR #179, whose predecessor-bound transport gate is intentionally non-controlling.

## Customer-facing question

Recorded snapshot statuses are displayed as **historical statements from supplied snapshots**, not freshly recomputed verdicts. The machine record explicitly has snapshot_state_reverified_at_review=false. Input signatures are inspected by the transport gate; neither that verification nor a previously recorded established state establishes current source-semantic validity.

A reviewer needs three distinct answers across revisions: (1) whether OVK's current typed Protected Effect claim is established by its supported model; (2) whether old signed evidence passes a narrow historical reuse eligibility gate; and (3) whether that old evidence is independently authorized for reliance. These are separate judgments.

The new reviewer adapter and script emit a Markdown review and schema-versioned JSON, preserving the exact source/target record identifiers, **field-level differences in caller-supplied guarantee specifications** (including changed statement and assumptions), evidence digests, and gate reason codes. It displays supplied statements for reviewer context while explicitly withholding authentication of their governing Git manifests. The adapter delegates historical transport to PR #179; it adds **no new verifier**, no evidence reuse permission, and no semantic widening.

## Development acceptance scenarios

The test fixture is synthetic, constructed from OVK Assurance IR objects rather than actual FastAPI source extraction. It uses the existing sealed Protected Effect evaluation and reuse machinery, with signed source evidence and directly reissued target evidence.

| Scenario | Current target typed claim | Historical predecessor gate | Reviewer outcome |
| --- | --- | --- | --- |
| Same declared guarantee, unchanged PE slice, signed directly linked reuse | established | conditional candidate | review; authenticate manifests, live policy, and source semantics before reliance |
| Edited descriptive guarantee statement, same typed PE slice | established | not admitted: definition changed | fresh evidence or independent review |
| Modified governing assumption, same typed PE slice | established | not admitted: definition changed | fresh evidence or independent review |
| Wrong signature-verification key | modeled target state still established under separately supplied original key | not admitted: invalid signature | review; no reliance |
| Missing target guarantee state | unknown | not admitted | review; no reliance |
| Historical signature and recorded reuse valid, but manifest/time authority not independently established | established | conditional candidate | still NO production reliance |

The word "established" here is scoped to OVK's typed Protected Effect machine claim. It is not a proof of the English guarantee statement or of all Python authorization behavior. A changed statement does not imply the typed machine claim was violated, and an ineligible transport is not a counterexample to that typed claim.

## Reproducible execution

On the draft branch with the supported Python dependencies installed:

    pytest -q tests/test_guarantee_assurance_state.py -k advisory

The integration test constructs two full signed evidence envelopes and invokes the reviewer CLI with six JSON artifacts. It asserts the exact non-controlling output and that an existing output directory is not overwritten.

To use the CLI on separately collected OVK records:

    python scripts/guarantee_continuity_review.py \
      --source-snapshot source-snapshot.json \
      --target-snapshot target-snapshot.json \
      --source-spec source-guarantee.json \
      --target-spec target-guarantee.json \
      --source-evidence source-pe-evidence.json \
      --target-evidence target-pe-evidence.json \
      --signature-key-file verification-key.bin \
      --guarantee-id G-REFUND \
      --output-dir reviewer-record

Outputs:

- reviewer-record/continuity-review.json — versioned structured statuses, reason codes, exact evidence identifiers, trust-limit flags, decision scope, and next action
- reviewer-record/continuity-review.md — reviewer-ready explanatory report with explicit NO on production reliance

The signature key is used for checking the supplied evidence and is never copied into the report. The output directory must not exist beforehand. Do not check private signing keys into Git; use a controlled local key file and review artifact confidentiality before sharing.

## Trust boundaries and blockers

1. **Governing manifest authentication:** source and target GuaranteeSpec are supplied by the caller. Matching their digests against snapshots does not prove they came from the governing manifest at the named source/target Git revisions. The report always says not_authenticated.
2. **Live reuse policy:** the historical gate does not re-evaluate expiry, revocation, signer authorization, and current-time relying policy. The report always says not_evaluated.
3. **Source semantics and extractor completeness:** the signed evidence is about OVK's admitted Assurance IR, not a source-language refinement proof. The report always says unproved.
4. **Production authority:** the report always sets production_reliance_authorized to false and decision_scope to advisory_only. These fields cannot be toggled using the public function or CLI.
5. **Temporal and revision identity:** do not turn the fixture revision names into real, immutable customer commit SHA claims. A real pilot must capture exact Git revisions and authenticate the extractor and manifest acquisition.
6. **Security:** input signing keys used in tests are illustrative. Output data may be sensitive. This CLI is a research/customer demonstration and does not implement secure multi-tenant evidence storage.

The CLI is a renderer/evaluation adapter for *collected evidence*, not a real FastAPI source extractor or an authorized CI gate.

## Pilot usefulness gate and next work

Show this report to a real security/backend reviewer and record whether (i) separate typed-claim and continuity states resolve a concrete PR ambiguity, (ii) the reason codes lead to the correct next revalidation action, and (iii) the unresolved trust fields are intelligible rather than overwhelming.

Do not count fixture test success as independent adoption or accuracy. Pilot issue #20 tracks maintainer permission, natural PR selection, signed/reproducible inputs, adjudication, setup cost, and actual reviewer time. Issue #216 is the executive control point.

The next customer-relevant implementation is an authenticated, version-bound source/target governing-manifest reader and a clearly separated live-time relying-policy evaluator, **if** actual reviewer feedback justifies that work. Neither mechanism should be silently merged into this advisory demo. PR #179 remains draft and non-controlling.
