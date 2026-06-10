# Security Policy

OVK is security-sensitive infrastructure because it may influence pull-request merge decisions and evidence claims.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | yes |
| 1.0.x | yes |
| &lt; 1.0 | no |

Report security issues against `main` or the latest release tag.

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
