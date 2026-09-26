# Resource identity provenance v1

Resource binding is meaningful only if OVK has an explicit model of resource
identity. The v1 model is deliberately restricted.

## Terms

Each ResourceRef may carry an identity term:

- symbol(name): an unconstrained resource key supplied by program state or input;
- literal(value): a concrete resource key.

No arbitrary call expression is interpreted as resource identity.

## Declared loader semantics

A source profile may declare that a loader preserves identity through one
argument. For example:

    resource_loader_identity_args = {
        "load_invoice": 0
    }

For:

    invoice = load_invoice(invoice_id)

the extractor may assign:

    invoice.identity_term = symbol("invoice_id")

This is an explicit repository/profile assumption. OVK does not infer that
load_invoice has these semantics from its name.

## Equality verification

For a required equality ResourceBinding:

1. identical canonical terms pass structurally;
2. distinct literals fail with a direct counterexample;
3. symbolic terms are encoded as Z3 strings and OVK asks whether inequality is
   satisfiable;
4. missing identity terms, unsupported relations, or missing Z3 produce UNKNOWN.

A satisfiable inequality is a counterexample relative to the declared identity
model. It is not a claim about arbitrary source semantics beyond that model.

This design keeps the source-extraction assumption visible:

    source semantics -> identity term -> resource-binding query

Each arrow is a separate trust obligation.
