"""Finite GitHub Actions matrix evaluation (WP-10)."""

from __future__ import annotations

import itertools
from typing import Any

_MAX_MATRIX_COMBINATIONS = 256


def evaluate_matrix(strategy: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[str]]:
    """Expand a job strategy.matrix into a finite combination list.

    Returns (combinations, unsupported). Unbounded or non-object matrices force review.
    """
    unsupported: list[str] = []
    if not isinstance(strategy, dict):
        return [], []
    matrix = strategy.get("matrix")
    if matrix is None:
        return [], []
    if not isinstance(matrix, dict):
        return [], ["matrix_not_object"]

    axes: dict[str, list[Any]] = {}
    include = matrix.get("include") if isinstance(matrix.get("include"), list) else []
    exclude = matrix.get("exclude") if isinstance(matrix.get("exclude"), list) else []
    for key, value in matrix.items():
        if key in {"include", "exclude"}:
            continue
        if not isinstance(value, list):
            unsupported.append(f"matrix_axis_not_list:{key}")
            continue
        if not value:
            unsupported.append(f"matrix_axis_empty:{key}")
            continue
        axes[str(key)] = list(value)

    if unsupported and not axes and not include:
        return [], unsupported

    keys = sorted(axes)
    combos: list[dict[str, Any]] = []
    if keys:
        for values in itertools.product(*(axes[k] for k in keys)):
            combos.append(dict(zip(keys, values)))
    else:
        combos = [{}]

    # Apply include (additive) and exclude (subtractive) conservatively.
    for item in include:
        if isinstance(item, dict):
            combos.append(dict(item))
    if exclude:
        filtered: list[dict[str, Any]] = []
        for combo in combos:
            drop = False
            for ex in exclude:
                if isinstance(ex, dict) and all(combo.get(k) == v for k, v in ex.items()):
                    drop = True
                    break
            if not drop:
                filtered.append(combo)
        combos = filtered

    if len(combos) > _MAX_MATRIX_COMBINATIONS:
        return [], [f"matrix_explosion:{len(combos)}> {_MAX_MATRIX_COMBINATIONS}".replace("> ", ">")]
    return combos, unsupported
