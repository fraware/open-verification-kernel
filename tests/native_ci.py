"""Helpers for gating native-backend integration tests in CI."""

from __future__ import annotations

import importlib.util
import os
import shutil


def skip_unless_native_backend(binary_name: str) -> bool:
    """Skip unless the binary is available locally or tier-1 CI installs it."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return os.environ.get("OVK_NATIVE_BACKEND") != binary_name
    return shutil.which(binary_name) is None


def skip_unless_z3() -> bool:
    """Skip Z3 integration unless tier-1 CI installs z3-solver."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return os.environ.get("OVK_NATIVE_BACKEND") != "z3"
    return importlib.util.find_spec("z3") is None
