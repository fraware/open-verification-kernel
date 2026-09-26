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

The profile marks control flow, dynamic guard effect names, unsupported call
signatures, syntax errors, and missing head material as unsupported semantics.
A strict product surface must not upgrade partial or unknown extraction coverage
to an allow decision.
