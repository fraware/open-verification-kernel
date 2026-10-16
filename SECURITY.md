# Security Policy

OVK is security-sensitive infrastructure because it may influence pull-request merge decisions and evidence claims.

## Release and security support status

**Last reviewed:** 2026-10-15. The latest publicly published release is `v1.2.1`. The `v1.3.0-rc.1` tag and distribution are **not published**. A historical version appearing in this table does not establish that it receives backported security fixes.

| Version | Public release and support status |
|---|---|
| `1.2.1` | Latest published release; the maintainer must explicitly confirm the security-patch support commitment |
| `1.1.x`, `1.0.x` | Historical versions; earlier documentation marked these supported, but ongoing security maintenance is not independently verified |
| Before `1.0` | No support claim |
| `1.3.0-rc.1` | Unpublished engineering candidate; no public install or security-support claim |

Report suspected vulnerabilities affecting the published release or current source tree through a **private** channel. Do not assume that reporting a problem against an old series creates a backport commitment.

## Reporting a vulnerability

Use the repository's private vulnerability-reporting / security advisory interface if available; otherwise contact the repository maintainer privately before sharing exploit details. If no private reporting path is available, the maintainers must configure one before a wider security-sensitive launch.

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
