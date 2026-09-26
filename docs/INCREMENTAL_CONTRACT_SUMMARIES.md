# Incremental Contract Summaries

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
