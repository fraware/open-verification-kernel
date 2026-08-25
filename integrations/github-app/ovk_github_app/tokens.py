"""Short-lived GitHub App installation tokens (no long-lived PATs)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from ovk_github_app.errors import TokenError

# GitHub allows App JWTs for at most 10 minutes.
DEFAULT_APP_JWT_LIFETIME_SECONDS = 600
# Installation tokens from GitHub expire in ~1 hour; we treat anything longer as policy failure.
MAX_INSTALLATION_TOKEN_LIFETIME_SECONDS = 3600


@dataclass(frozen=True)
class InstallationToken:
    """Ephemeral installation access token."""

    installation_id: int
    token: str
    expires_at: int
    permissions: dict[str, str]

    def remaining_seconds(self, *, now: int | None = None) -> int:
        current = int(time.time()) if now is None else int(now)
        return max(0, int(self.expires_at) - current)

    def is_expired(self, *, now: int | None = None, skew_seconds: int = 30) -> bool:
        return self.remaining_seconds(now=now) <= skew_seconds


HttpPoster = Callable[[str, dict[str, str], bytes | None], tuple[int, dict[str, Any]]]


def _default_http_json(
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 — GitHub API only
            raw = response.read().decode("utf-8")
            payload = json.loads(raw) if raw else {}
            return int(response.status), payload if isinstance(payload, dict) else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"message": raw}
        if not isinstance(payload, dict):
            payload = {"message": raw}
        return int(exc.code), payload


def build_app_jwt(
    *,
    app_id: str | int,
    private_key_pem: str,
    now: int | None = None,
    lifetime_seconds: int = DEFAULT_APP_JWT_LIFETIME_SECONDS,
) -> str:
    """Create a short-lived RS256 JWT for GitHub App authentication.

    Requires PyJWT + cryptography at runtime. Unit tests inject a signer or mock
    the exchange HTTP layer instead of minting real JWTs.
    """
    if lifetime_seconds <= 0 or lifetime_seconds > DEFAULT_APP_JWT_LIFETIME_SECONDS:
        raise TokenError(
            f"app JWT lifetime must be in 1..{DEFAULT_APP_JWT_LIFETIME_SECONDS} seconds"
        )
    try:
        import jwt
    except ImportError as exc:  # pragma: no cover - optional runtime dep
        raise TokenError("PyJWT is required to mint GitHub App JWTs") from exc

    current = int(time.time()) if now is None else int(now)
    payload = {
        "iat": current - 60,  # GitHub recommends clock skew cushion
        "exp": current + int(lifetime_seconds),
        "iss": str(app_id),
    }
    try:
        return jwt.encode(payload, private_key_pem, algorithm="RS256")
    except Exception as exc:  # noqa: BLE001 — surface as TokenError
        raise TokenError(f"failed to mint app JWT: {exc}") from exc


@dataclass
class InstallationTokenProvider:
    """Exchange installation tokens on demand; never persist long-lived PATs.

    Tokens are cached in memory only until ``expires_at`` (minus skew). There is
    no API to store a classic ``ghp_`` personal access token.
    """

    app_id: str | int
    private_key_pem: str
    api_base: str = "https://api.github.com"
    http_post: HttpPoster = _default_http_json
    jwt_builder: Callable[..., str] | None = None
    _cache: dict[int, InstallationToken] | None = None

    def __post_init__(self) -> None:
        if self._cache is None:
            self._cache = {}

    def get_token(
        self,
        installation_id: int,
        *,
        now: int | None = None,
        force_refresh: bool = False,
    ) -> InstallationToken:
        current = int(time.time()) if now is None else int(now)
        cached = (self._cache or {}).get(int(installation_id))
        if cached is not None and not force_refresh and not cached.is_expired(now=current):
            return cached
        token = self._exchange(installation_id, now=current)
        assert self._cache is not None
        self._cache[int(installation_id)] = token
        return token

    def clear_cache(self, installation_id: int | None = None) -> None:
        assert self._cache is not None
        if installation_id is None:
            self._cache.clear()
        else:
            self._cache.pop(int(installation_id), None)

    def _exchange(self, installation_id: int, *, now: int) -> InstallationToken:
        builder = self.jwt_builder or build_app_jwt
        app_jwt = builder(
            app_id=self.app_id,
            private_key_pem=self.private_key_pem,
            now=now,
        )
        url = f"{self.api_base.rstrip('/')}/app/installations/{int(installation_id)}/access_tokens"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "ovk-github-app-alpha",
        }
        status, payload = self.http_post(url, headers, b"{}")
        if status not in (200, 201):
            raise TokenError(f"installation token exchange failed: HTTP {status}")
        token = str(payload.get("token", "") or "")
        if not token:
            raise TokenError("installation token exchange returned empty token")
        if token.startswith("ghp_") or token.startswith("github_pat_"):
            raise TokenError("refusing long-lived personal access token material")
        expires_at = _parse_expires_at(payload.get("expires_at"))
        lifetime = expires_at - now
        if lifetime <= 0 or lifetime > MAX_INSTALLATION_TOKEN_LIFETIME_SECONDS:
            raise TokenError(
                f"installation token lifetime out of policy: {lifetime}s "
                f"(max {MAX_INSTALLATION_TOKEN_LIFETIME_SECONDS}s)"
            )
        permissions = payload.get("permissions") if isinstance(payload.get("permissions"), dict) else {}
        return InstallationToken(
            installation_id=int(installation_id),
            token=token,
            expires_at=expires_at,
            permissions={str(k): str(v) for k, v in permissions.items()},
        )


def _parse_expires_at(raw: Any) -> int:
    if raw is None:
        raise TokenError("installation token missing expires_at")
    if isinstance(raw, (int, float)):
        return int(raw)
    text = str(raw).strip()
    # GitHub returns ISO-8601 UTC, e.g. 2026-07-25T17:00:00Z
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        from datetime import datetime

        return int(datetime.fromisoformat(text).timestamp())
    except ValueError as exc:
        raise TokenError(f"invalid expires_at: {raw!r}") from exc
