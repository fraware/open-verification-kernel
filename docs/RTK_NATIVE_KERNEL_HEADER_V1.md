# Native Lean kernel-header observations — development v1

**Exact pinned version:** Lean 4.14.0. **Research-only:** stacked on draft #199; all production reliance flags remain false. Tracked scientific obligation: #195. Prospective evaluation gate: #177.

## Concrete finding: the default kernel trust level is nonzero

The tagged Lean 4.14.0 source `src/Lean/Environment.lean` defines `EnvironmentHeader.trustLevel` and `EnvironmentHeader.quotInit`. Imported `.olean` file hashes do not directly encode the runtime values of these fields.

In the repository's **actual separately installed pinned source and target Lean CLI processes**, native `run_cmd` observations report:

- **`trustLevel = 1025`**. Imported modules are assumed to have been checked; these invocations do **not** establish independent kernel verification of every imported module.
- **`quotInit = true`**.
- The values are the same in the original source theorem and both target unproved-claim contexts.

This invalidates the earlier inference that the ordinary pinned native development control meets a zero-trust environment premise. The prior baseline candidate from #197–199 was always non-controlling and conditional; under the stricter policy here, it now **abstains**, as required.

## Implemented guard

The new `lean_native_kernel_header_v1.lean.txt` footer executes in native source-checked theorem and target *unproved claim* processes. It reads the true `env.header.trustLevel` and `env.header.quotInit`, returns a typed root/kind-bound record and explicitly excludes historical target proof replay and reliance authority.

The pre-oracle validator accepts exactly one header witness per context with strict root identity, schema and primitive type validation. For this restricted development contract, a candidate needs both `trustLevel = 0` and `quotInit = true`. Other actual states produce **`UNRESOLVED`**, with `unsupported_nonzero_kernel_trust_level` or `unsupported_kernel_quotient_state`, and no reuse candidate. Malformed, forged-authority or missing witnesses raise an error.

The native workflow now seals **two `UNRESOLVED` pre-oracle statuses** before the independent target replay; historical proof admissibility observations are recorded separately. A green oracle under trusted imported modules does **not** authorize reuse or change the pre-oracle decision.

Synthetic Python tests exercise trust-level mismatches, quotient-state disagreements, wrong root, duplicates and malformed records. Their zero-trust positive fixture is not evidence that the ordinary native CLI supplies that premise. The real native workflow instead asserts the observed `1025` value and reports `PINNED_LEAN_NONZERO_TRUST_LEVEL_OBSERVED_REUSE_DISABLED`.

## Deliberately rejected native mutation shortcut

An attempted development control used a Lean `Environment` record update to force `quotInit = false` within a target process. The pinned kernel correctly rejected the attempt because the `Environment` constructor is **private**. That failed run is not evidence of a successfully realized quotient-state drift. The invalid mutation was removed. The Python validator still has negative tests for the relevant record condition, clearly distinguished from native kernel observation.

Never use `unsafe` constructor bypasses or invented environment-state mutations to make the test pass.

## What remains

- A source and target import-check protocol actually run at **trust level zero**, using supported Lean CLI mechanisms, with exact module/checker identity and coverage evidence.
- A separate native quotient-state compatibility experiment implemented through supported environment construction APIs, if this state can be obtained safely. No such native control is claimed here.
- A binding between genuine source-kernel-check evidence, trusted imported modules and the target context, plus complete native semantic support for the allowed proof fragment.
- Independent authentication of the source certificate and target specification, axiom policy, revocation, expiry and relying authority.
- A formal bridge from any restricted model to actual Lean kernel checking, and blinded prospective adjudication under #177.

The model theorem proved in #199 is still only for the declared first-order evaluator. Even genuine zero-trust kernel runs would not themselves discharge all these other assumptions. Keep this PR draft and unmerged; never promote `UNRESOLVED` or `CONDITIONAL_IDENTITY_CANDIDATE` to production `VALID`.
