# Protected Effect Integrity v1

Protected Effect Integrity is OVK's first Assurance-IR theorem family.

The intended semantic property is:

    Performed(principal, effect, resource)
        implies
    Authorized(principal, effect, resource)

The v1 compiler does not claim to prove that property over source code. It
decomposes each ProtectedEffect into explicit structural sub-obligations:

- guard presence on a semantic path;
- principal binding;
- effect binding;
- resource binding;
- path attachment.

Resource identity receives deliberately conservative treatment.

If the authorization guard and protected effect reference the same ResourceRef,
the structural resource check is established.

If they reference different resources and the IR contains an explicit
ResourceBinding, the result is UNKNOWN until a verifier establishes that binding.

If they reference different resources and no binding obligation exists, the
structural result is VIOLATED.

This prevents an asserted binding from being silently treated as proof.

When body-bound CFG dominance evidence is present, effective, and coverage-
complete, the compiler may use that evidence for guard-to-sink ordering.
Incomplete coverage, unresolved spans, or opaque control flow remain UNKNOWN.
Value-origin and closed-world bypass-authority evidence may justify an
independent bypass path; missing writers or incomplete worlds never become a
false PASS.

The compiler does not produce an OVK merge decision. Source-profile extraction,
control-flow dominance, binding proof, backend execution, evidence aggregation,
and policy enforcement remain separate steps.
