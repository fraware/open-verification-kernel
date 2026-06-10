"""Surface-aware backend routing preferences."""

from __future__ import annotations

SURFACE_BONUS = 0.85


def surface_backend_bonuses(changed_files: list[str]) -> dict[str, float]:
    """Return per-backend utility bonuses inferred from changed file surfaces."""
    normalized = [path.replace("\\", "/").lower() for path in changed_files]
    if any(path.endswith(".als") or "/alloy/" in path for path in normalized):
        return {"alloy": SURFACE_BONUS}
    if any(path.endswith(".dfy") or "/dafny/" in path for path in normalized):
        return {"dafny": SURFACE_BONUS}
    if any(path.endswith(".lean") or "/lean/" in path for path in normalized):
        return {"lean": SURFACE_BONUS}
    if any(path.endswith((".c", ".h")) or "/cbmc/" in path for path in normalized):
        return {"cbmc": SURFACE_BONUS}
    if any("verus" in path for path in normalized):
        return {"verus": SURFACE_BONUS}
    if any(path.endswith(".rs") for path in normalized):
        return {"kani": SURFACE_BONUS}
    if any("iam" in path or "/policy" in path or path.endswith("_policy.tf") for path in normalized):
        return {"cedar": SURFACE_BONUS}
    if any("deploy" in path or "deployment" in path or "/release" in path for path in normalized):
        return {"tla+": SURFACE_BONUS}
    return {}
