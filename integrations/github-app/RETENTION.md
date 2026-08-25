# OVK GitHub App — retention policy

Private-alpha data retention for `integrations/github-app/`.

## TTL defaults

| Data class | Location | TTL | Notes |
|---|---|---|---|
| Webhook delivery-id dedupe records | In-memory store (process) / optional durable store | **24 hours** | Matches replay window + clock skew cushion; expired IDs may be reclaimed |
| Webhook timestamp skew window | Request validation | **5 minutes** (`±300s`) | Rejects stale stamped deliveries |
| Installation access tokens | Memory only | **≤ 1 hour** (GitHub-issued) | Never persisted as long-lived PATs; refreshed on demand |
| App JWT (issuer assertion) | Ephemeral | **≤ 10 minutes** | Minted per exchange; not stored |
| Per-installation event receipts | `{data}/installations/{id}/data/events/` | **7 days** | Operator may shorten; deleted immediately on uninstall |
| Per-installation cache objects | `{data}/installations/{id}/cache/` | **24 hours** | Keys always include `installation_id` + `repo_id` |
| Credentials material | `{data}/installations/{id}/credentials/` | Until uninstall | App private key is operator-managed outside this tree when possible |

## Uninstall

On `installation.deleted`, all files under `{data}/installations/{installation_id}/` are removed and in-memory tokens for that installation are cleared. See `ovk_github_app.cleanup.handle_installation_deleted`.

## Operator overrides

| Environment variable | Default | Purpose |
|---|---|---|
| `OVK_WEBHOOK_MAX_SKEW_SECONDS` | `300` | Timestamp skew tolerance |
| `OVK_GITHUB_APP_DATA` | `.ovk-github-app` | Root for installation partitions |
| `OVK_WEBHOOK_REQUIRE_TIMESTAMP` | `1` | Require `X-OVK-Timestamp` (unix seconds) on webhooks |

When running behind a trusted ingress that cannot stamp `X-OVK-Timestamp`, set `OVK_WEBHOOK_REQUIRE_TIMESTAMP=0`. Delivery-id dedupe remains mandatory.

## Public path

Retention here applies only to the private-alpha App. The composite Action (`action.yml`) does not store installation partitions; CI artifacts follow the consumer workflow's retention settings.
