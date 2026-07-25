"""Redacted logging helpers for the GitHub App alpha."""

from __future__ import annotations

import logging
import re
from typing import Any

# Home / user path prefixes (aligned with ovk.core.evidence_integrity.redact_path intent).
_HOME_PREFIX = re.compile(
    r"^(?:"
    r"(?i:[a-z]:)/Users/[^/]+|"
    r"/Users/[^/]+|"
    r"/home/[^/]+"
    r")"
)
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(authorization:\s*bearer\s+)(\S+)"),
    re.compile(r"(?i)(x-hub-signature-256:\s*)(\S+)"),
    re.compile(r"(ghp_[A-Za-z0-9_]{20,})"),
    re.compile(r"(github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"(ghs_[A-Za-z0-9_]{20,})"),
    re.compile(r"(-----BEGIN[^-]+PRIVATE KEY-----)(.*?)(-----END[^-]+PRIVATE KEY-----)", re.DOTALL),
    re.compile(r"(?i)(webhook[_-]?secret|client[_-]?secret|private[_-]?key)\s*[:=]\s*(\S+)"),
)


def redact_path(path: str) -> str:
    """Scrub account home prefixes from filesystem paths."""
    raw = str(path).strip()
    if not raw:
        return raw
    normalized = raw.replace("\\", "/")
    match = _HOME_PREFIX.match(normalized)
    if match:
        rest = normalized[match.end() :].lstrip("/")
        return f"<home>/{rest}" if rest else "<home>"
    drive = re.match(r"^(?i:[a-z]:)(/.*)?$", normalized)
    if drive:
        rest = (drive.group(1) or "").lstrip("/")
        return f"<drive>/{rest}" if rest else "<drive>"
    return normalized


def redact_secrets(text: str) -> str:
    """Scrub bearer tokens, PATs, and PEM private key material from log text."""
    out = str(text)
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3 and "PRIVATE KEY" in pattern.pattern:
            out = pattern.sub(r"\1<redacted-pem>\3", out)
        elif pattern.groups >= 2 and (
            "authorization" in pattern.pattern.lower()
            or "signature" in pattern.pattern.lower()
            or "secret" in pattern.pattern.lower()
        ):
            out = pattern.sub(r"\1<redacted>", out)
        else:
            out = pattern.sub("<redacted-token>", out)
    return out


def redact_message(message: str) -> str:
    """Redact a free-form log message (paths embedded in prose + secrets)."""
    scrubbed = redact_secrets(message)
    scrubbed = re.sub(
        r"(?P<p>(?:/Users/|/home/|(?i:[a-z]:)/Users/)[^\s\"']+)",
        lambda m: redact_path(m.group("p")),
        scrubbed,
    )
    scrubbed = re.sub(
        r"(?P<p>(?i:[a-z]:)\\[^\s\"']+|(?i:[a-z]:)/[^\s\"']+)",
        lambda m: redact_path(m.group("p")),
        scrubbed,
    )
    return scrubbed


def redact_text(text: str) -> str:
    """Apply path and secret scrubbing suitable for operator logs."""
    return redact_message(text)


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs paths and secrets from record messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        redacted = redact_message(msg)
        record.msg = redacted
        record.args = ()
        return True


def attach_redacting_filter(logger: logging.Logger | None = None) -> logging.Filter:
    """Attach :class:`RedactingFilter` to ``logger`` (default root)."""
    target = logger or logging.getLogger()
    filt = RedactingFilter()
    target.addFilter(filt)
    return filt


def safe_log_extra(data: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy with string values redacted."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, str):
            out[key] = redact_message(value)
        else:
            out[key] = value
    return out
