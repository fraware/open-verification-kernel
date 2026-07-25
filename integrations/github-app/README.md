# OVK GitHub App (private alpha)

Private-alpha GitHub App for Open Verification Kernel. **Not a Marketplace listing.**

The **composite Action** (`action.yml`) remains the supported public integration path. This App is an optional alpha surface with explicit security controls (OVK-08 / OVK-PR7).

## Controls

| Control | Implementation |
|---|---|
| Webhook signature verification | HMAC-SHA256 (`X-Hub-Signature-256`); missing/invalid rejected |
| Replay protection | `X-OVK-Timestamp` skew (±300s) + `X-GitHub-Delivery` dedupe store |
| Installation isolation | `{data}/installations/{id}/` partitions for credentials, cache, data |
| Least-privilege permissions | `manifest.json`: `checks:write`, `contents:read`, `pull_requests:read`, `metadata:read` |
| Short-lived installation tokens | On-demand exchange; App JWT ≤10m; installation token ≤1h; no PATs |
| Redacted logs | Paths and secrets scrubbed via `RedactingFilter` |
| Idempotent Check Run updates | `external_id` = `ovk:{repo}:{head_sha}` (same as Action / PR6) |
| No cross-repository cache reuse | Cache keys require `installation_id` + `repo_id` |
| Uninstall cleanup | `installation.deleted` deletes the partition |
| Retention policy | [RETENTION.md](RETENTION.md) |

## Layout

```text
integrations/github-app/
  manifest.json          # GitHub App manifest (public: false)
  RETENTION.md           # TTL policy
  requirements.txt       # Optional runtime (FastAPI, PyJWT, …)
  README.md              # This file
  ovk_github_app/        # Python package
```

## Operator setup (alpha)

1. Create a **private** GitHub App from `manifest.json` (GitHub → Settings → Developer settings → GitHub Apps → New GitHub App, or manifest flow). Do not set the App public / Marketplace.
2. Generate a webhook secret; set `OVK_GITHUB_WEBHOOK_SECRET`.
3. Download the App private key PEM; set `OVK_GITHUB_APP_ID` and `OVK_GITHUB_APP_PRIVATE_KEY` (or mount the PEM for token exchange).
4. Point the App webhook URL at your deployed `/webhook` endpoint.
5. Install the App on a pilot org/repo with the default least-privilege permissions only.

### Run the webhook service

```bash
pip install -r integrations/github-app/requirements.txt
export OVK_GITHUB_WEBHOOK_SECRET='...'
export OVK_GITHUB_APP_DATA='.ovk-github-app'
# Optional: ingress must stamp X-OVK-Timestamp (unix seconds) unless disabled:
# export OVK_WEBHOOK_REQUIRE_TIMESTAMP=0
cd integrations/github-app
uvicorn ovk_github_app.service:create_app --factory --host 0.0.0.0 --port 8080
```

Health: `GET /healthz`  
Webhook: `POST /webhook`

### Headers

| Header | Required | Purpose |
|---|---|---|
| `X-Hub-Signature-256` | yes | `sha256=<hmac>` over raw body |
| `X-GitHub-Delivery` | yes | Delivery-id dedupe |
| `X-GitHub-Event` | yes | Event name |
| `X-OVK-Timestamp` | default yes | Unix seconds; must be within skew |

GitHub does not send a webhook timestamp header natively. For alpha, stamp `X-OVK-Timestamp` at a trusted ingress, or set `OVK_WEBHOOK_REQUIRE_TIMESTAMP=0` and rely on delivery-id dedupe (documented trade-off in RETENTION.md).

## Tokens

Use `InstallationTokenProvider` to exchange short-lived installation tokens on demand. The provider refuses `ghp_` / `github_pat_` material and rejects lifetimes above one hour. Do not configure a classic PAT for this App.

## Check runs

Idempotent updates use the same `external_id` scheme as the Action:

```text
ovk:{owner}/{repo}:{head_sha}
```

## Tests

From the repository root (pythonpath includes this package):

```bash
pytest tests/test_github_app_signature.py tests/test_github_app_replay.py tests/test_github_app_isolation.py tests/test_github_app_controls.py -q
```

## Status

Alpha alongside the composite Action. Do not advertise Marketplace availability. Uninstall cleanup and retention TTLs are mandatory for any private pilot.
