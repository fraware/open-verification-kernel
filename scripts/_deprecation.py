"""Deprecation helpers for legacy maintainer scripts."""

from __future__ import annotations

import sys
import warnings


def warn_deprecated_script(*, script: str, replacement: str) -> None:
    """Emit a deprecation warning pointing users to the supported CLI command."""
    message = f"{script} is deprecated; use `{replacement}` instead."
    warnings.warn(message, DeprecationWarning, stacklevel=2)
    print(f"warning: {message}", file=sys.stderr)
