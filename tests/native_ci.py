"""Helpers for gating native-backend integration tests in CI."""

from __future__ import annotations

import os
import shutil


def skip_unless_native_backend(binary_name: str) -> bool:
    """Skip unless the binary is available locally or tier-1 CI installs it."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return os.environ.get("OVK_NATIVE_BACKEND") != binary_name
    return shutil.which(binary_name) is None
