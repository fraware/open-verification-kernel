# Incremental FastAPI Assurance IR Fragments

The FastAPI Protected Effect source profile supports dependency-aware reuse of
already-bound per-file semantic IR fragments.

## Fragment identity

Each FastApiFileSemanticFragment records:

- source path and exact source digest;
- complete profile semantic digest;
- exact stable-name -> contract_id dependencies consumed by that file;
- unsupported constructs found during binding;
- principals, resources, effects, guards;
- Protected Effects and resource bindings;
- contract uses;
- semantic paths.

A fragment is reusable only if:

    source_digest unchanged
    AND profile_digest unchanged
    AND every consumed contract version unchanged

Otherwise the file summary is rebound.

## Full and incremental compilers share one binder

The ordinary FastApiDependencyEffectExtractor and incremental compiler use the
same bind_route_file_summary implementation and the same
assemble_fastapi_assurance_ir implementation.

This prevents semantic drift between full and incremental paths.

## Dependency-aware examples

Unchanged head:

    N reusable file fragments
    0 rebound fragments

One unrelated file changes:

    N-1 reusable fragments
    1 rebound fragment

A service contract changes while its route source remains unchanged:

    service file fragment rebounds because its source changed
    consuming route fragment rebounds because contract_id changed
    unrelated fragments are reused

The route therefore observes the new service semantics even though its source
and RouteFileSummary were unchanged.

A profile change conservatively invalidates every bound fragment because sink,
guard, effect, or binding meaning may change.

## Full-compile equivalence

Incremental compilation is accepted only as an optimization. Tests compare the
complete canonical Assurance IR payload from incremental compilation against a
fresh full compile for:

- initial compile;
- unchanged head revision;
- unrelated-file change;
- service-contract change;
- profile change;
- removed file.

The payloads must be identical.

## Remaining global work

Function contracts are still globally recomposed from lightweight summary
candidates each compile, and the complete Assurance IR object is assembled.

The next optimization can use the contract dependency graph to incrementally
recompose only changed direct contracts and their forwarding dependents.

At that point source analysis, route binding, and contract composition all have
work proportional to changed input plus affected dependency closure.
