"""Typed failures for the GitHub App alpha controls."""

from __future__ import annotations


class GitHubAppError(Exception):
    """Base error for the private-alpha GitHub App service."""


class SignatureError(GitHubAppError):
    """Webhook HMAC signature missing or invalid."""


class ReplayError(GitHubAppError):
    """Webhook rejected by timestamp skew or delivery-id dedupe."""


class IsolationError(GitHubAppError):
    """Cross-installation or cross-repository boundary violation."""


class TokenError(GitHubAppError):
    """Installation token exchange or lifetime policy failure."""
