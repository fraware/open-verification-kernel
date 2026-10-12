# External Lean release-history replay — development case

**Evidence status:** exploratory historical-repository development control,
**not** a prospectively sealed case and not RTK prediction-performance data.

The historical repository, file, release pair and theorem were inspected
before this protocol was written. These data are therefore **development**
and cannot support a confirmatory false-reuse statistic or an independently
selected unbiased sample. The distinct frozen v0/v1 repository-selection
ledgers and their outcomes remain untouched.

## Exact externally governed source materials

- Upstream: https://github.com/leanprover/lean4
- Source release: `v4.14.0` / commit
  `410fab7284703f41660ca2454218dcca9b2ec896`
- Target release: `v4.15.0` / commit
  `11651562caae0a0b3973811508db2ab8903d3854`
- Exact path in each commit: `doc/examples/tc.lean`
- Source Git blob: `c6c3cd21a7ef1e1ae0b5bff7625e941cb93379e9`
- Target Git blob: `2b8252f7442fcd860a860a8241752e107096ab01`
- Historical theorem: `HasType.det`, as a complete Lean source declaration
  and proof script beginning with `theorem HasType.det`.
- The external file changed across these releases. Direct inspection shows a
  change in explanatory documentation, with the selected theorem and proof
  text unchanged. This must be independently checked byte-for-byte by the
  source/target workflow before asserting a replay result.

Git object identifiers are verified by the CI checkout and Git's object
hash function. SHA-256 values for the complete source and target contents,
and separately the extracted theorem, are recorded in the emitted JSON.

## Native experiment

Run
`.github/workflows/rtk-external-lean-history-v2.yml`. This fetches both
full 40-character upstream commit identities using the SHA-pinned
`actions/checkout`, checks exact Git blob identities, pins Lean 4.14.0 to
the executable digest previously measured by the development workflow,
and executes both complete Lean source files with the same Lean checker.

A `VALID`-like result is `historical_evidence_applicability=ADMISSIBLE`
only if:

1. the historical theorem source bytes and target theorem bytes are identical;
2. each complete upstream file is an independently authenticated Git object;
3. the original source file passes a real native Lean check;
4. the target file passes a real native Lean check under the same fixed
   experimental checker build.

If the target fails a native check, the result is **UNDETERMINED**, not
inapplicability of this particular theorem and not target refutation.
Errors elsewhere in the file or incompatibility with the 4.14.0 checker could
explain rejection independently of the selected historical proof.

## Important limitations

This is **historical Lean proof-*source* replay**, not a portable byte-level
replay of a serialized/elaborated Lean kernel certificate. The same Lean
source proof script could elaborate differently in another context.
There is no independent theorem proving semantic preservation of the
entire environment across these releases. Native acceptance establishes
the exact checked file under the experimental Lean checker and its trust
assumptions, not a general library evolution theorem.

The target upstream release is Lean 4.15.0, while the experiment deliberately
holds the checking tool at 4.14.0. The target environment for this restricted
experiment is thus **the changed source file under the fixed old checker**,
not the native canonical Lean 4.15.0 release environment. A broader study
needs both canonical source/target toolchain checks and a declared
cross-version policy or proof-certificate migration rule.

The entire file is checked, so any unproved `axiom`, `sorry`, arbitrary
import or broader unsafe compilation semantics in that file require separate
review before the observed PASS would count as independent evidence for a
formal claim. The operator/CLI verification itself is not an attestation
from an external trusted third party. CI artifact authenticity and signing
are separate provenance questions.

## Next independent sampling rule

The next **prospective** corpus must freeze, before looking at target
outcomes or SUT predictions:

- an exact repository universe and discovery order;
- exact source/target release or revision selection;
- a typed extraction criterion for each theorem and its context;
- native source acceptance and target checking toolchains;
- old-proof-byte identity and admissibility rules, policy assumptions,
  abstention rules and adverse-case controls;
- an isolated prediction-before-oracle execution plan.

The current development case is explicitly ineligible for that holdout.
