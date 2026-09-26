# Incremental Python Semantic Summaries

The Python authorization contract inferencer supports content-addressed
per-file semantic summaries.

Each ContractFileSummary stores:

- the source content digest;
- direct FunctionContract objects established in that file;
- transparent forwarding candidates needed for interprocedural composition.

## Cross-revision reuse

ContractSummaryIndex is built from parsed Python materials.

For an unchanged path+source digest, a prior ContractFileSummary is reused
without walking that file's AST for contract semantics.

For a changed/new digest, the file is summarized again.

The index records:

    fresh_summary_count
    reused_summary_count

and carries the complete path->source-digest map used to validate it against head
materials.

## Global composition

Reusing a wrapper summary does not reuse a stale composed contract.

The global composition step takes the current set of direct contracts and all
forwarding candidates, then recomputes composed contracts to a fixed point.

Example:

    AgentRepository.get  [changed file]
             |
             v
    AgentService.get     [unchanged/reused file summary]

If AgentRepository.get changes, AgentService.get is recomposed from the current
callee contract. Its contract_id changes because the digest includes the callee
contract version.

This preserves the contract-impact graph even when the wrapper source itself is
unchanged.

## Compiler boundary

FastApiDependencyEffectExtractor.compile accepts an optional
contract_summary_index.

The index is accepted only if its complete source-digest map matches the supplied
head materials. A stale index fails closed.

The historical API remains valid. If no summary index is supplied, one is built
from the current parsed AST index.

## Current boundary

This removes repeated AST semantic analysis for unchanged files during function
contract inference.

Route/dependency/service-call extraction still walks all supplied FastAPI ASTs.
Global contract recomposition also iterates forwarding summaries, although it no
longer needs source ASTs.

The next step toward end-to-end O(delta) extraction is a reusable per-file route
and protected-effect syntax summary followed by dependency-aware semantic
rebinding.


## FastAPI route summaries

The same content-addressed reuse mechanism now covers bounded FastAPI route
syntax.

A RouteFileSummary records profile-independent syntax facts:

- static HTTP method and normalized route path;
- handler source provenance;
- whether unsupported control flow is present;
- dependency parameter names and source locations;
- constructor aliases used to resolve service-call targets;
- calls and their positional/keyword arguments;
- symbolic resource terms;
- argument non-null facts derived from the handler signature.

The summary deliberately excludes policy meaning. It does not decide which call
is a protected sink, which dependency authorizes which effect, which resource
binding relation applies, or which FunctionContract is current.

Every compile rebinds an unchanged route summary against:

    current FastApiDependencyEffectProfile
    current FunctionContract set

Therefore:

- changing the profile changes extracted effects/bindings even if route source is
  unchanged;
- changing a service contract changes the route's contract use and coverage even
  if the route summary is reused;
- stale route summary indexes fail closed on source-digest mismatch.

## Remaining full-repository work

With AST, contract, and route summaries reusable, source AST walking for unchanged
files is removed from these bounded extraction stages.

Global recomposition still processes the lightweight summary graph, and the
compiler still assembles the complete Assurance IR for the head revision.

Further optimization should focus on dependency-aware recomposition and
persistent summary storage across worker processes, rather than weakening the
semantic rebinding boundary.
