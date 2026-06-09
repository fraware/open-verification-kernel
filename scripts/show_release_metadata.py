#!/usr/bin/env python
"""Print OVK release metadata."""

from __future__ import annotations

import json

from ovk.core.release_metadata import release_metadata


def main() -> int:
    print(json.dumps(release_metadata(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
