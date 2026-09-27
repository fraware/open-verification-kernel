# Automatic Pull Request Assurance Diff

For repositories that declare durable guarantees and the supported FastAPI
Protected Effect profile, ordinary `ovk check` can now derive a source-grounded
Assurance Diff automatically.

The pipeline is:

    trusted base guarantees
        +
    trusted base Protected Effect profile
        +
    exact Git base/head source materials
        |
        v
    base Assurance IR ---- head Assurance IR
        |                      |
        |                      +---- incremental Protected Effect verification
        |                                   |
        +---- current evidence               +---- fresh or strictly reused evidence
                    \                         /
                     v                       v
                      GuaranteeAssuranceSnapshot
                               |
                               v
             Code Diff + Guarantee Diff + Assurance Diff

Protected Effect evidence remains shadow/non-controlling. This feature does not
change the existing OVK merge-decision lattice.

## Repository files

Durable guarantees:

    .verification/guarantees.json

FastAPI Protected Effect extraction semantics:

    .verification/protected-effects.fastapi.json

Both are semantic authority. For pull-request evaluation, the versions from the
exact base revision are authoritative. Head/workspace edits are proposals only.

## Protected Effect profile

The profile schema is:

    ovk.protected_effect_profile.v1

It declares:

- repository-relative Python source path patterns;
- protected sink calls and namespaced effects;
- resource identity and scope argument semantics;
- source-derived contract bindings;
- explicit scope-assertion helper semantics;
- parameter dependency guards and the effects they authorize;
- direct route-decorator dependencies for bounded static capability mediation;
- static sink capability/resource identities;
- resource-binding projection/relation semantics;
- bounded source file and byte limits.

OVK does not infer these semantics heuristically from naming conventions.

### Route-level candidate mediation

The supported route-level syntax subset is intentionally narrow. A profile may
declare a protected sink as acting on a static endpoint/capability resource and
associate a direct FastAPI route dependency with that same static resource and
effect.

For example:

    @router.post("", dependencies=[Depends(require_auth)])
    async def endpoint(request):
        ...
        await dispatch(...)

FastAPI evaluates the direct route dependency before entering the handler, so
its presence is source-grounded evidence of handler-entry mediation. That fact
does **not** establish that `require_auth` is an effective authorization
decision. A dependency may return normally in an unauthenticated configuration,
delegate to helpers with unresolved semantics, or rely on startup invariants
outside the handler.

OVK therefore records the dependency as a candidate guard with:

    effectiveness = unproved

Protected Effect Integrity carries a separate `guard_effectiveness` proof
obligation. Source coverage can be complete when the route-dependency syntax,
static resource, effect, and entrypoint dominance are all represented, while the
security claim remains UNKNOWN until source-derived semantics establish the
dependency's fail-closed authorization behavior.

This separation is deliberate: extraction coverage measures representational
completeness; guard effectiveness measures proof discharge. An unresolved proof
must not be disguised as missing source coverage.

The extractor does not generalize the syntax rule to dependency factories,
dynamic dependency collections, or request-derived resource authorization.
Static sink configuration is mutually exclusive with dynamic sink identity,
scope, source-contract, and resource-binding declarations.

Repository-wide coverage may remain partial because of unsupported code outside
the relevant claim. Protected Effect evaluation, sealed evidence, and product
qualification use effect-local coverage only when every relevant semantic path
carries explicit local coverage metadata; otherwise they fall back to global
Assurance IR coverage.

### Source-derived authorization dependency contracts

A route dependency with `effectiveness = unproved` may be upgraded only from
source-derived contract evidence that matches trusted profile expectations.

The first contract family recognizes a narrow fail-closed credential equality:

    async def require_auth(credentials = Depends(...)):
        if not credentials or credentials.credentials != ACTIVE_TOKEN:
            raise HTTPException(...)

Normal completion establishes that the credential was present and passed the
configured equality check. The trusted base profile separately declares the
credential expression and authority expression that count for that dependency.

The inferencer rejects successful early returns, additional conditional control
flow, loops, try/except, delegated helpers, and other unsupported forms. Such
dependencies remain unproved.

The governed credential/authority expression pair defines the authorization
predicate accepted by policy. Source inference proves that every supported
normal-return path passed that predicate. It does not prove initialization,
secrecy, non-nullness, or provenance of the authority value; those are separate
obligations for future source-derived invariant semantics.

## Exact source acquisition

For pull requests, source files are loaded from Git objects for the exact base
and head SHAs. The working tree is not treated as a substitute for either
revision.

If either revision or a selected source material cannot be read, the automatic
Assurance Diff is unavailable.

## Evidence authentication

Automatic durable guarantee state requires authenticated evidence.

Set:

    OVK_SIGNING_KEY

in the verification environment.

If no signing identity is available, Code Diff and Guarantee Diff still render,
while the source-derived Assurance Diff is explicitly unavailable.

## Historical evidence reuse

Fresh verification does not require a reusable runtime fingerprint.

Strict cross-run evidence reuse additionally requires:

    OVK_WORKER_IMAGE_DIGEST

The runtime fingerprint also binds OVK, Python/platform identity, Protected
Effect checker version, resource-binding checker version, and installed Z3
version.

If worker-image identity is absent, OVK performs fresh Protected Effect checks.
It never substitutes a weaker cache key.

## Policy identity

Protected Effect evidence is bound to a policy digest covering:

- the trusted verification policy;
- the trusted durable guarantee-manifest digest;
- the trusted Protected Effect profile digest;
- Protected Effect checker identity and version.

Changing any of these prevents historical evidence from being silently reused
under a different semantic authority.

## Failure semantics

Unsupported source constructs are recorded by the source extractor and reduce
coverage. Complete PASS assurance requires complete coverage.

Missing base/head materials, an unavailable trusted profile, an unavailable
guarantee manifest, missing signing identity, extraction failure, evidence
admission failure, or snapshot inconsistency produces an explicit unavailable or
open Assurance Diff.

These conditions never manufacture an established guarantee.
