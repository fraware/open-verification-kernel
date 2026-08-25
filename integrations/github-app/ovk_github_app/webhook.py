"""Webhook request processing with required security controls."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ovk_github_app.cache_keys import app_cache_key
from ovk_github_app.check_runs import app_check_run_external_id, build_check_run_update_payload
from ovk_github_app.cleanup import handle_installation_deleted
from ovk_github_app.errors import GitHubAppError, ReplayError, SignatureError
from ovk_github_app.isolation import InstallationStore
from ovk_github_app.redact import RedactingFilter, redact_message
from ovk_github_app.replay import (
    DEFAULT_MAX_SKEW_SECONDS,
    DELIVERY_HEADER,
    TIMESTAMP_HEADER,
    DeliveryDedupeStore,
    MemoryDeliveryDedupeStore,
    protect_against_replay,
)
from ovk_github_app.signature import SIGNATURE_HEADER, verify_signature
from ovk_github_app.tokens import InstallationTokenProvider

logger = logging.getLogger("ovk_github_app.webhook")
logger.addFilter(RedactingFilter())


@dataclass
class WebhookResult:
    status_code: int
    body: dict[str, Any]


@dataclass
class WebhookProcessor:
    """Verify, dedupe, isolate, and dispatch GitHub App webhook events."""

    webhook_secret: str
    store: InstallationStore
    dedupe: DeliveryDedupeStore = field(default_factory=MemoryDeliveryDedupeStore)
    token_provider: InstallationTokenProvider | None = None
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS
    require_timestamp_header: bool = True

    def process(
        self,
        *,
        headers: dict[str, str],
        body: bytes,
        now: int | None = None,
    ) -> WebhookResult:
        current = int(time.time()) if now is None else int(now)
        normalized = {_normalize_header(k): v for k, v in headers.items()}
        try:
            verify_signature(
                secret=self.webhook_secret,
                body=body,
                signature_header=normalized.get(SIGNATURE_HEADER.lower()),
            )
            timestamp_raw = normalized.get(TIMESTAMP_HEADER.lower())
            if timestamp_raw is None and not self.require_timestamp_header:
                timestamp_raw = str(current)
            protect_against_replay(
                delivery_id=normalized.get(DELIVERY_HEADER.lower()),
                timestamp=timestamp_raw,
                store=self.dedupe,
                now=current,
                max_skew_seconds=self.max_skew_seconds,
            )
            event = normalized.get("x-github-event", "")
            payload = json.loads(body.decode("utf-8") or "{}")
            if not isinstance(payload, dict):
                raise GitHubAppError("webhook payload must be a JSON object")
            return self._dispatch(event=event, payload=payload, now=current)
        except SignatureError as exc:
            logger.warning(redact_message(f"webhook signature rejected: {exc}"))
            return WebhookResult(401, {"error": "invalid_signature", "detail": str(exc)})
        except ReplayError as exc:
            logger.warning(redact_message(f"webhook replay rejected: {exc}"))
            return WebhookResult(409, {"error": "replay_rejected", "detail": str(exc)})
        except (GitHubAppError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(redact_message(f"webhook processing failed: {exc}"))
            return WebhookResult(400, {"error": "bad_request", "detail": str(exc)})

    def _dispatch(self, *, event: str, payload: dict[str, Any], now: int) -> WebhookResult:
        action = str(payload.get("action", "") or "")
        installation = payload.get("installation") if isinstance(payload.get("installation"), dict) else {}
        installation_id = installation.get("id")
        repository = payload.get("repository") if isinstance(payload.get("repository"), dict) else {}
        repo_id = repository.get("id")
        full_name = str(repository.get("full_name") or "")

        if event == "installation" and action == "deleted":
            result = handle_installation_deleted(
                payload,
                store=self.store,
                token_provider=self.token_provider,
            )
            return WebhookResult(200, {"ok": True, "handled": "installation.deleted", **result})

        if installation_id is not None:
            # Touch the installation partition so credentials/data stay isolated.
            self.store.partition(int(installation_id))

        if event in {"check_suite", "pull_request", "push"} and installation_id and repo_id:
            cache_key = app_cache_key(
                installation_id=int(installation_id),
                repo_id=int(repo_id),
                namespace=event,
                components={"action": action, "delivery_bound": True},
            )
            head_sha = _extract_head_sha(event, payload)
            external_id = (
                app_check_run_external_id(repo=full_name or "unknown/repo", head_sha=head_sha)
                if head_sha
                else None
            )
            check_payload = None
            if head_sha and full_name:
                check_payload = build_check_run_update_payload(
                    repo=full_name,
                    head_sha=head_sha,
                    conclusion="neutral",
                    title="OVK GitHub App alpha",
                    summary="Private alpha acknowledged event; composite Action remains the public path.",
                    status="in_progress",
                )
            self.store.write_json(
                int(installation_id),
                f"events/{event}-{now}.json",
                {
                    "event": event,
                    "action": action,
                    "repo_id": int(repo_id),
                    "cache_key": cache_key,
                    "external_id": external_id,
                    "check_run": check_payload,
                },
            )
            return WebhookResult(
                200,
                {
                    "ok": True,
                    "handled": event,
                    "installation_id": int(installation_id),
                    "repo_id": int(repo_id),
                    "cache_key": cache_key,
                    "external_id": external_id,
                },
            )

        if installation_id is not None:
            return WebhookResult(
                200,
                {
                    "ok": True,
                    "handled": event or "unknown",
                    "installation_id": int(installation_id),
                    "action": action,
                },
            )
        return WebhookResult(200, {"ok": True, "handled": event or "unknown", "action": action})


def _normalize_header(name: str) -> str:
    return str(name).strip().lower()


def _extract_head_sha(event: str, payload: dict[str, Any]) -> str | None:
    if event == "push":
        sha = payload.get("after")
        return str(sha) if sha else None
    if event == "pull_request":
        pr = payload.get("pull_request") if isinstance(payload.get("pull_request"), dict) else {}
        head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
        sha = head.get("sha")
        return str(sha) if sha else None
    if event == "check_suite":
        suite = payload.get("check_suite") if isinstance(payload.get("check_suite"), dict) else {}
        sha = suite.get("head_sha")
        return str(sha) if sha else None
    return None
