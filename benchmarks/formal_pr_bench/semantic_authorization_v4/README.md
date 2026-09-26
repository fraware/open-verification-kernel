# Semantic Authorization v4 development cases

This directory exercises generic interprocedural contract composition beyond
tenant/workspace scope.

The initial case binds a project authorization guard to a source-derived
postcondition over the returned document:

    authorized_project.identity == returned_document.project_id

The service contract is inferred from an explicit rejecting guard. The secure
route passes the authorized project_id into the service. The regression passes a
different project parameter, allowing Z3 to produce a counterexample.

These are public development cases, not protected holdouts.
