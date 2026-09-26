# Interprocedural Contract Calculus v1

OVK's interprocedural contract layer is a small serializable predicate language,
not an embedded Python theorem language.

The v1 terms are:

- parameter(name)
- return_attribute(name)
- literal(value)

The v1 predicates are:

- non_null(parameter)
- eq(term, term)

A function contract has a qualified callable name, positional parameter order,
preconditions, postconditions, and exact source provenance.

For example, source of the form:

    async def get(self, agent_id, *, workspace_id=None):
        agent = ...
        if agent.id != agent_id:
            return None
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

may yield:

    pre:
      non_null(parameter("workspace_id"))

    post:
      eq(return_attribute("id"), parameter("agent_id"))
      eq(return_attribute("workspace_id"), parameter("workspace_id"))

The call-site extractor resolves the concrete callable, substitutes actual
arguments, establishes required preconditions, and materializes every established
return attribute on ResourceRef.attribute_terms.

Profiles then select which established properties become proof obligations.
Examples:

    returned id -> ResourceRef.identity_term
    returned workspace_id -> ResourceRef.scope_term

or an arbitrary parent relation:

    authorized.identity == acted.attribute["project_id"]

A source-derived property that is not selected by the profile remains semantic
metadata. An unresolved selected property lowers extraction coverage and prevents
PASS.

## Composition with Provability Fabric

The shape intentionally mirrors PF Core's pre/post contract algebra while
remaining data-oriented and decidable. A later adapter can translate supported
OVK contract predicates into a PF Core/Lean contract without putting arbitrary
Python code inside the trusted representation.

## Current proof boundary

The inferencer recognizes explicit rejecting guards before a unique successful
return. It does not infer ORM semantics, aliasing semantics, arbitrary loops,
exception behavior, or general functional correctness.

Its claims are local:

    successful return + established preconditions
        => selected return-attribute equalities

Call-site and resource-binding proofs remain separate steps with separate
provenance and evidence.
