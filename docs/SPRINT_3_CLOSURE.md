# Sprint 3 Closure

Sprint 3 is functionally complete for the authorization path.

Completed:

- Authorization obligations.
- Query-polarity preservation.
- Solver-independent SMT plans.
- Optional Z3 execution.
- Z3 result normalization.
- First-class authorization evidence construction.
- Regression artifact rendering and file emission.
- Validated authorization path.
- Stable adapter routed through the deterministic validated path.
- First-class `ovk auth-obligation` command.
- Authorization input schema.
- Runtime validation and schema tests.
- Adversarial validation coverage.
- Authorization obligation scorer protected through pytest.

Remaining limitations:

- Direct workflow editing for the scorer remains blocked.
- External smoke testing still requires an integration repository.
- Additional malformed benchmark fixture files may be added later.

Status:

Sprint 3 can be treated as closed for repository-internal development. The next sprint should start the infrastructure exposure path.
