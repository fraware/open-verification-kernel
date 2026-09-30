# FastAPI Protected Effects AST profile

Profile identifier:

    assurance.fastapi.protected_effects.ast_v1

This is an experimental source-to-Assurance-IR extractor. It is separate from
authorization.fastapi.ast_v1 and does not change existing authorization-lane
decisions.

The first supported pattern is intentionally narrow:

    @app.post("/invoices/{invoice_id}/refund")
    def refund(invoice_id: str, user):
        invoice = load_invoice(invoice_id)
        authorize(user, "billing.invoice.refund", invoice)
        issue_refund(invoice)

Repository policy supplies the guard function names and maps protected sink
function names to namespaced effects.

For each supported handler the extractor emits source-grounded principals,
resources, effects, authorization guards, protected effects, semantic paths, and
resource-binding obligations.

If the guard authorizes one resource expression and the sink acts on another, the
extractor emits a required equality ResourceBinding. The binding itself is not
proof. Protected Effect Integrity keeps that dimension UNKNOWN until a verifier
establishes the relationship.

Supported handlers may attach a bounded CFG summary. When guard and sink spans
resolve to CFG nodes and sink-local coverage is complete, guard dominance can
become authoritative; otherwise the result stays UNKNOWN rather than a false
PASS. Flat `and`/`or` BoolOps expand into short-circuit-aware branches; nested
or opaque BoolOps remain outside the envelope.

Value-origin provenance classifies ordinary FastAPI entry-handler parameters
and `request.state` attributes. Parameters of helper functions remain unresolved
until caller provenance is established. Identifier spelling such as `settings`
or `CONFIG_*` does not establish server authority. Conditional state writes stay
UNKNOWN until their control provenance is proved. Closed-world bypass analysis
refuses authorized PASS when its writer world is incomplete. Open WebUI bypass
checks are development replay only and do not rewrite frozen external-candidate
labels.

The profile marks unsupported loops/try/match/with, dynamic guard effect names,
unsupported call signatures, syntax errors, and missing head material as
unsupported semantics. A strict product surface must not upgrade partial or
unknown extraction coverage to an allow decision.
