# Lean 4.14 separate installed-environment comparison

**Status:** development-only, no target historical-proof replay, no transport
soundness theorem, no independent experimental calibration. This extends the
same pre-exposed definition-drift fixtures used in PRs #184–#186.

## What is new

The source and target now run under **two separately installed** Lean
4.14.0 toolchain directory trees, provisioned via isolated `ELAN_HOME`
roots in one pinned GitHub Actions runner. Each executable is individually
checked against measured Lean binary SHA-256:

`eacf754d25ae86ea076882a34b9444f2485659d9df4266b821443b28ca95a215`.

The runner verifies distinct executable filesystem paths and inodes.
The Python comparison refuses the same toolchain root, executable inode,
or reused hardlinked `.olean` module files. It hashes every loaded module
file reported by Lean in **each installation**, records individual file
SHA-256 digests and a canonical inventory digest, and reports module
additions, deletions and byte-level drift.

The target is still an explicitly **unproved goal placeholder**:

`axiom rtk_unproven_target_claim (n : Nat) : op n = n`

used only for native claim/type/dependency introspection. No historical
source proof term is supplied to the target, and the target receives no
fresh proof. The old source proof's imported constants are looked up
read-only in both independently instantiated Lean environments.

The implementation and executable development controls are:

- `experiments/rtk/lean_dual_installed_env_v1.py`
- `tests/test_rtk_lean_dual_installed_env_v1.py`
- `.github/workflows/rtk-lean-dual-installed-env-v1.yml`

## Evidence interpretation

`BYTE_IDENTICAL` establishes that the *reported loaded module files*
in the two on-disk installations have matching paths and SHA-256 bytes
under the matching pinned binary. `DRIFT_DETECTED` identifies concrete
module byte differences. Neither outcome establishes the applicability
of a historical proof to a target theorem.

The module inventory is acquired by Lean's imported-module enumeration
under `import Lean`, which produced 1,012 modules in the preceding
single-installation control. It does not independently certify that all
dependencies of Lean's interpretation, native elaboration, runtime,
platform ABI, plugin behavior, other runtime files, environment variables
or relying policies were captured.

The two toolchain roots are distinct, with individual module files.
**Both installations use the same pinned upstream release and bootstrap
distribution, share a GitHub runner and are administered by the same
workflow.** Separate file trees are not independently governed builds
or independent third-party attestations.

The success condition for this *positive reproducibility control* is
identical installed module bytes under two independently provisioned
roots. A source/target **cross-version** comparison, differing module
contents and stable module names still need adversarial native tests
with independently constructed toolchains.

## Critical declared negative claims

The evidence report permanently fixes:

- `independently_administered_builds_verified=false`
- `module_dependency_semantic_closure_proved=false`
- `cross_version_compatibility_proved=false`
- `historical_proof_replayed_on_target=false`
- `fresh_target_proof_supplied=false`
- `target_claim_established=false`
- `native_transport_oracle_executed=false`
- `transport_applicability=UNDETERMINED`
- `reliance_authorization=false`

The tests reject identical toolchain roots and inodes, hardlinked module
files, symlinked installations, unregistered checker binaries and
malformed native goal declarations. A changed target module is classified
as `DRIFT_DETECTED` while historical transport stays `UNDETERMINED`.

### Remaining path to credible applicability decisions

The next gate is a typed, authenticated connection from native
source-proof expressions through their closed dependencies to a
target environment under a specified checker and policy. Need separate
experiment paths for proof elaboration, kernel-term checking and
claim truth. In particular, the Lean `Expr.repr` diagnostics here are
not a proved canonical serialization, and `.olean` identity cannot
stand in for an independent checker oracle. Source/target version drift
and a prospective, prediction-before-oracle test remain open.

The whole experiment is research-only and must not enter OVK's
deployment, merge, security or relying decision gates.
