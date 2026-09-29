# Incremental Function-Contract Composition

The FastAPI Protected Effect compiler can reuse composed FunctionContract objects
across revisions instead of running the complete forwarding fixed point on every
compile.

## Stable graph

Per-file ContractSummary objects provide:

- direct FunctionContract objects;
- transparent ForwardingContractCandidate objects.

For incremental composition, each direct contract is keyed by its stable
qualified name and semantic contract_id. Each forwarding candidate has a digest
over its complete substitution semantics and source provenance.

A forwarding edge is:

    wrapper qualified name -> callee qualified name

## Invalidation

Changed seeds are the union of:

- added, removed, or version-changed direct contracts;
- added, removed, or fingerprint-changed forwarding candidates.

The invalidation closure is computed over the union of the previous and current
forwarding graphs.

Using both graphs is necessary for sound removals and rewires.

Example:

    Repository.get
         |
         v
    Service.get
         |
         v
    Facade.get

A Repository.get contract change invalidates exactly:

    Repository.get
    Service.get
    Facade.get

An unrelated ServiceB.get chain stays reusable.

## Reuse

An existing composed contract is reused only if:

- its stable name is outside the invalidation closure;
- the forwarding candidate still exists;
- the candidate fingerprint is unchanged;
- its direct callee edge is unchanged.

Every invalidated or newly available forwarding candidate is recomposed using
the current contract graph.

Direct contracts come directly from the current content-bound file summaries.

## Conservative fallback

Multiple forwarding candidates with the same wrapper stable name have
order-sensitive semantics in the v1 full composer. The incremental composer
does not invent a new tie-break rule. It falls back to full composition for that
case.

Initialization also uses the existing full composer to establish baseline state.

## FastAPI integration

IncrementalFastApiCompilationState now retains the contract-composition state.

The resulting pipeline is:

    changed source
      -> cached/rebuilt per-file summaries
      -> changed direct/candidate contract seeds
      -> transitive contract dependency closure
      -> reused/recomposed function contracts
      -> dependency-valid reused/rebound route fragments
      -> complete Assurance IR

A low-level contract change therefore recomposes its contract dependents and
rebinds only route fragments that consume changed contract versions.

## Equivalence requirement

Incremental composition is an optimization only.

Tests compare every resulting FunctionContract set against
compose_function_contracts(), and the FastAPI integration compares the complete
canonical Assurance IR against a fresh full compile for unchanged graphs, direct
contract changes, forwarding rewires, and removals.

The intended work bound is:

    O(changed direct/candidate summaries + transitive forwarding dependents)

for contract composition, plus the already dependency-aware route-fragment
binding work.
