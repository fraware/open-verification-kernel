"""Secret redaction for assurance configuration and environment exports."""

from __future__ import annotations

import re
from typing import Any, Mapping

from ovk.assurance.pcs_hash import sha256_digest
from ovk.core.execution_budget import _SECRET_ENV_DENYLIST

REDACTION_POLICY_ID = "ovk-redact-v1"

_SECRET_NAME_RE = re.compile(
    r"(?:^|_)(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|"
    r"CREDENTIAL|CONN(?:ECTION)?[_-]?STRING|JWT|BEARER|AUTH)(?:_|$)",
    re.IGNORECASE,
)

_SECRET_VALUE_RE = re.compile(
    r"(?:"
    r"ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|Bearer\s+[A-Za-z0-9\-._~+/]+=*"
    r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    r")",
    re.IGNORECASE,
)

_EXTRA_SECRET_KEY_TOKENS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "CONNECTION_STRING",
    "CONN_STRING",
    "PGPASSWORD",
    "MYSQL_PWD",
    "DATABASE_URL",
    "JWT",
)


def is_secret_key(key: str) -> bool:
    """Return True when *key* matches the denylist or secret name patterns."""
    upper = key.upper()
    if upper in _SECRET_ENV_DENYLIST:
        return True
    if upper in _EXTRA_SECRET_KEY_TOKENS:
        return True
    if _SECRET_NAME_RE.search(key):
        return True
    for token in _EXTRA_SECRET_KEY_TOKENS:
        if token in upper:
            return True
    return False


def looks_like_secret_value(value: Any) -> bool:
    """Return True when *value* matches high-confidence secret value patterns."""
    if not isinstance(value, str) or not value:
        return False
    return _SECRET_VALUE_RE.search(value) is not None


def redact_environment(
    environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    """Redact secret-bearing environment entries.

    Returns a PCS-shaped redacted_environment object::

        {
          "redaction_policy_id": "ovk-redact-v1",
          "entries": {...},
          "redacted_keys": [...],
          "environment_digest": "sha256:..."
        }
    """
    entries: dict[str, str] = {}
    redacted_keys: list[str] = []
    for key, value in sorted((environment or {}).items(), key=lambda item: item[0]):
        text = str(value)
        if is_secret_key(key) or looks_like_secret_value(text):
            redacted_keys.append(key)
            continue
        entries[str(key)] = text
    payload = {
        "redaction_policy_id": REDACTION_POLICY_ID,
        "entries": entries,
        "redacted_keys": sorted(set(redacted_keys)),
    }
    payload["environment_digest"] = sha256_digest(
        {"entries": entries, "redacted_keys": payload["redacted_keys"], "policy": REDACTION_POLICY_ID}
    )
    return payload


def redact_mapping(data: Mapping[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    """Return a copy of *data* with secret keys/values removed, plus redacted paths."""
    cleaned: dict[str, Any] = {}
    redacted: list[str] = []
    for key, value in (data or {}).items():
        key_s = str(key)
        if is_secret_key(key_s):
            redacted.append(key_s)
            continue
        if isinstance(value, dict):
            nested, nested_redacted = redact_mapping(value)
            cleaned[key_s] = nested
            redacted.extend(f"{key_s}.{item}" for item in nested_redacted)
        elif isinstance(value, list):
            nested_list: list[Any] = []
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    nested_item, nested_redacted = redact_mapping(item)
                    nested_list.append(nested_item)
                    redacted.extend(f"{key_s}[{index}].{path}" for path in nested_redacted)
                elif looks_like_secret_value(item):
                    redacted.append(f"{key_s}[{index}]")
                else:
                    nested_list.append(item)
            cleaned[key_s] = nested_list
        elif looks_like_secret_value(value):
            redacted.append(key_s)
        else:
            cleaned[key_s] = value
    return cleaned, sorted(set(redacted))
