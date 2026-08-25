import json
from pathlib import Path

import pytest

from ovk.core.adapter_runtime import execute_obligations


def _auth_input() -> dict:
    return json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))


def test_enforced_execution_does_not_reuse_legacy_flat_cache(tmp_path: Path) -> None:
    obligation = {
        "lane": "authorization",
        "intent_id": "no-admin-route-bypass",
        "input": _auth_input(),
    }
    legacy = execute_obligations(
        [obligation],
        {},
        repo="example/repo",
        head_sha="head",
        cache_dir=tmp_path,
        use_cache=True,
        parallel=False,
        policy={"routing": {"mode": "legacy"}},
    )[0]
    assert legacy.routing_enforced is not True
    assert list(tmp_path.glob("*.json"))

    enforced = execute_obligations(
        [obligation],
        {},
        repo="example/repo",
        head_sha="head",
        cache_dir=tmp_path,
        use_cache=True,
        parallel=False,
        policy={
            "routing": {
                "mode": "enforced",
                "enforced_lanes": ["authorization"],
                "prefer_deterministic": True,
                "max_selected_backends": 1,
            },
            "budget": {"allowed_backends": ["authorization-deterministic"]},
        },
    )[0]
    assert enforced.routing_enforced is True
    assert enforced.schema_version == "ovk.evidence.v3"
    assert enforced.selected_backends == ["authorization-deterministic"]
    compatibility_routes = [
        item
        for item in enforced.generated_artifacts
        if isinstance(item, dict) and item.get("kind") == "backend_routing"
    ]
    assert compatibility_routes == []


def test_enforced_execution_rejects_mismatched_caller_routing(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="invalid caller routing decision"):
        execute_obligations(
            [
                {
                    "lane": "authorization",
                    "intent_id": "no-admin-route-bypass",
                    "input": _auth_input(),
                }
            ],
            {
                "no-admin-route-bypass": {
                    "intent_id": "no-admin-route-bypass",
                    "selected": [{"backend": "legacy-z3"}],
                    "rejected": [],
                }
            },
            repo="example/repo",
            head_sha="head",
            cache_dir=tmp_path,
            use_cache=True,
            parallel=False,
            policy={
                "routing": {
                    "mode": "enforced",
                    "enforced_lanes": ["authorization"],
                    "prefer_deterministic": True,
                    "max_selected_backends": 1,
                },
                "budget": {"allowed_backends": ["authorization-deterministic"]},
            },
        )


def test_shadow_mode_uses_only_control_plane_namespace_cache(tmp_path: Path) -> None:
    execute_obligations(
        [
            {
                "lane": "authorization",
                "intent_id": "no-admin-route-bypass",
                "input": _auth_input(),
            }
        ],
        {},
        repo="example/repo",
        head_sha="head",
        cache_dir=tmp_path,
        use_cache=True,
        parallel=False,
        policy={"routing": {"mode": "shadow"}},
    )
    assert list(tmp_path.glob("*.json")) == []
    assert (tmp_path / "control-plane").exists()
