# Assurance IR v1

Assurance IR is OVK's typed semantic interchange layer between source/framework extraction and verification obligations.

It is deliberately not verification evidence. A valid IR says that an extractor produced a well-formed semantic model with explicit provenance, coverage, assumptions, and unknowns. It does not say the source program satisfies any property.

## Pipeline position

~~~text
Repository change
        |
        v
Source/framework extractor
        |
        v
Assurance IR
        |
        v
Verification obligations
        |
        v
Backend routing and execution
        |
        v
Evidence / decision / attestation
~~~

The layer is additive in v1. Existing lanes do not consume it yet.

## Core objects

PrincipalRef identifies a human, service, agent, anonymous actor, or unresolved principal.

ResourceRef identifies the object acted upon. Resource identity may include a tenant expression.

EffectRef names a semantic effect such as billing.invoice.refund, identity.user.delete, or network.egress.

AuthorizationGuard relates a principal, effect, and resource at an authorization decision.

ProtectedEffect identifies a security-sensitive effect performed by the application.

BindingConstraint records a semantic relationship between two principals, effects, or resources. This is the basis for later principal/effect/resource binding obligations.

PathCondition records a source-derived condition relevant to a semantic path.

SemanticPath records an ordered application path from an entry point to a protected effect, including relevant guards and path conditions.

AssuranceClaim records a durable candidate or approved semantic claim. Claims carry origin and approval status and remain distinct from verification evidence.

## Provenance and uncertainty

Every source-derived object carries SourceProvenance:

- extractor identity and version;
- repository/base/head identity;
- source ranges;
- abstraction coverage;
- assumptions;
- notes.

Incomplete extraction must be represented as partial or unknown. Unsupported semantics must not silently disappear from the model.

## Identity

compute_assurance_ir_digest content-addresses the semantic snapshot. Set-like collections are sorted by stable IDs. Ordered call chains retain their order because that order may be semantically relevant.

seal_assurance_ir adds the computed digest to the IR. Parsing a sealed IR with a mismatched digest fails validation.

## Trust boundary

Assurance IR v1 does not prove that:

- the extractor is sound;
- the extractor found every path;
- a guard dominates a protected effect;
- an authorization decision refers to the same principal/effect/resource as the performed operation;
- any backend proof is valid.

Those are separate obligations.

The intended next property family is protected-effect integrity:

~~~text
Performed(principal, effect, resource)
    -> Authorized(principal, effect, resource)
~~~

Principal binding, effect binding, resource binding, and guard/path obligations should remain independently visible so that unknown remains explicit.
