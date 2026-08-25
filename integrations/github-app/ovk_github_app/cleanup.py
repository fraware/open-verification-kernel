"""Uninstall cleanup for installation-scoped data."""

from __future__ import annotations

import logging
from typing import Any

from ovk_github_app.isolation import InstallationStore
from ovk_github_app.redact import redact_message
from ovk_github_app.tokens import InstallationTokenProvider

logger = logging.getLogger(__name__)


def handle_installation_deleted(
    payload: dict[str, Any],
    *,
    store: InstallationStore,
    token_provider: InstallationTokenProvider | None = None,
) -> dict[str, Any]:
    """Delete installation-scoped data when GitHub sends ``installation.deleted``.

    Clears filesystem partitions and any in-memory installation tokens.
    """
    installation = payload.get("installation") if isinstance(payload.get("installation"), dict) else {}
    raw_id = installation.get("id")
    if raw_id is None:
        raise ValueError("installation.deleted payload missing installation.id")
    installation_id = int(raw_id)
    deleted = store.delete_installation(installation_id)
    if token_provider is not None:
        token_provider.clear_cache(installation_id)
    logger.info(
        redact_message(f"installation cleanup complete id={installation_id} deleted={deleted}")
    )
    return {
        "installation_id": installation_id,
        "deleted": deleted,
        "action": "installation.deleted",
    }
