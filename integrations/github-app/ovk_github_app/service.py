"""Minimal FastAPI (or Starlette) webhook service for the private alpha.

Runtime extras (not part of the core ``ovk`` package)::

    pip install -r integrations/github-app/requirements.txt

Core security modules and unit tests do not require FastAPI.
"""

from __future__ import annotations

import os
from pathlib import Path

from ovk_github_app.isolation import InstallationStore
from ovk_github_app.replay import MemoryDeliveryDedupeStore
from ovk_github_app.webhook import WebhookProcessor


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def build_processor() -> WebhookProcessor:
    secret = _env("OVK_GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        raise RuntimeError("OVK_GITHUB_WEBHOOK_SECRET is required")
    data_root = Path(_env("OVK_GITHUB_APP_DATA", ".ovk-github-app") or ".ovk-github-app")
    require_ts = (_env("OVK_WEBHOOK_REQUIRE_TIMESTAMP", "1") or "1") not in {"0", "false", "False"}
    max_skew = int(_env("OVK_WEBHOOK_MAX_SKEW_SECONDS", "300") or "300")
    return WebhookProcessor(
        webhook_secret=secret,
        store=InstallationStore(data_root),
        dedupe=MemoryDeliveryDedupeStore(ttl_seconds=86_400),
        max_skew_seconds=max_skew,
        require_timestamp_header=require_ts,
    )


def create_app():
    """Create the ASGI app. Imports FastAPI lazily so unit tests stay dep-light."""
    try:
        from fastapi import FastAPI, Header, Request, Response
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "fastapi is required to run the GitHub App service; "
            "install integrations/github-app/requirements.txt"
        ) from exc

    processor = build_processor()
    app = FastAPI(
        title="OVK GitHub App (private alpha)",
        version="0.1.0-alpha",
        docs_url=None,
        redoc_url=None,
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "surface": "github-app-alpha"}

    @app.post("/webhook")
    async def webhook(
        request: Request,
        x_hub_signature_256: str | None = Header(default=None),
        x_github_delivery: str | None = Header(default=None),
        x_github_event: str | None = Header(default=None),
        x_ovk_timestamp: str | None = Header(default=None),
    ) -> Response:
        body = await request.body()
        headers = {
            "X-Hub-Signature-256": x_hub_signature_256 or "",
            "X-GitHub-Delivery": x_github_delivery or "",
            "X-GitHub-Event": x_github_event or "",
            "X-OVK-Timestamp": x_ovk_timestamp or "",
        }
        # Drop empty optional timestamp so processor can apply require_timestamp policy.
        if not headers["X-OVK-Timestamp"]:
            del headers["X-OVK-Timestamp"]
        if not headers["X-Hub-Signature-256"]:
            del headers["X-Hub-Signature-256"]
        if not headers["X-GitHub-Delivery"]:
            del headers["X-GitHub-Delivery"]
        result = processor.process(headers=headers, body=body)
        return Response(
            content=__import__("json").dumps(result.body),
            status_code=result.status_code,
            media_type="application/json",
        )

    return app


app = None

try:
    if _env("OVK_GITHUB_WEBHOOK_SECRET"):
        app = create_app()
except Exception:
    # Import-time app construction is best-effort; operators call create_app().
    app = None
