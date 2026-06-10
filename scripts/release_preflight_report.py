#!/usr/bin/env python
"""Backward-compatible wrapper for the in-package release preflight report."""

from __future__ import annotations

from ovk.core.release_preflight_report import (  # noqa: F401
    build_release_preflight_report,
    main,
    parse_args,
)

if __name__ == "__main__":
    raise SystemExit(main())
