# Security Policy

OVK is security-sensitive infrastructure because it may influence pull-request merge decisions and evidence claims.

## Supported versions

The project is pre-v1. Report security issues against `main` until formal releases begin.

## Reporting a vulnerability

Please open a private security advisory if available, or contact the maintainers through the repository owner.

## Security-critical project rules

- Unknown, timeout, skipped, and adapter error outcomes must not be treated as pass in enforce mode.
- Evidence must include backend, version, assumptions, limits, input digest, and result.
- Agent-authored changes to OVK configuration or enforcement policy must require human review.
- Adapters must run with the minimum privileges required.
- Generated evidence must be bound to the commit SHA it evaluates.

## High-priority vulnerability classes

- Evidence forgery.
- Adapter sandbox escape.
- Unknown-result laundering.
- Agent self-approval or self-disable path.
- Backend guarantee misrepresentation.
- Incomplete-context claims presented as pass.
