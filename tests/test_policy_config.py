"""Tests for verification policy recipes and schema-backed config."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from ovk.core.capabilities import CapabilityRegistry
from ovk.core.context import budget_from_policy, load_verification_policy
from ovk.core.router import VerificationBudget, route_intent


POLICY_DOC = Path("docs/POLICY.md")
SCHEMA_PATH = Path("schemas/verification.config.schema.json")


def _load_recipe_map() -> dict[str, dict]:
    text = POLICY_DOC.read_text(encoding="utf-8")
    pattern = re.compile(
        r"## Recipe \d+: (?P<name>[^\n]+)\n.*?```yaml\n(?P<yaml>.*?)\n```",
        re.DOTALL,
    )
    recipes: dict[str, dict] = {}
    for match in pattern.finditer(text):
        payload = yaml.safe_load(match.group("yaml"))
        if isinstance(payload, dict):
            recipes[match.group("name").strip()] = payload
    return recipes


def test_all_recipes_validate_against_schema() -> None:
    recipes = _load_recipe_map()
    assert len(recipes) == 5
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    for name, recipe in recipes.items():
        errors = sorted(validator.iter_errors(recipe), key=lambda item: list(item.path))
        assert not errors, f"{name}: {errors}"


def test_recipe_budget_fields() -> None:
    recipes = _load_recipe_map()
    strict = budget_from_policy(recipes["Strict production"])
    assert isinstance(strict, VerificationBudget)
    assert "dafny" in strict.denied_backends
    assert strict.max_wall_time_seconds == 60.0

    bot = budget_from_policy(recipes["Security-sensitive bot PRs"])
    assert bot.allowed_backends == frozenset({"opa", "z3", "cedar"})
    assert bot.max_wall_time_seconds == 15.0

    full = budget_from_policy(recipes["Full formal stack"])
    assert full.max_memory_mb == 2048


def test_route_intent_rejections_match_recipe_budgets() -> None:
    recipes = _load_recipe_map()
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    intent = json.loads(Path("templates/authorization/no_admin_route_bypass.intent.json").read_text(encoding="utf-8"))

    deterministic_budget = budget_from_policy(recipes["Deterministic-only CI"])
    deterministic_decision = route_intent(intent, registry.all(), budget=deterministic_budget)
    deterministic_rejected = {item["backend"] for item in deterministic_decision["rejected"]}
    assert {"dafny", "verus", "lean", "kani"}.issubset(deterministic_rejected)

    security_budget = budget_from_policy(recipes["Security-sensitive bot PRs"])
    security_decision = route_intent(intent, registry.all(), budget=security_budget)
    selected = {item["backend"] for item in security_decision["selected"]}
    assert selected.issubset({"opa", "z3", "cedar"})


def test_load_verification_policy_from_yaml(tmp_path: Path) -> None:
    recipe = _load_recipe_map()["Advisory OSS default"]
    config = tmp_path / "config.yml"
    config.write_text(yaml.dump(recipe), encoding="utf-8")
    loaded = load_verification_policy(config)
    assert loaded["mode"] == "advisory"


def test_prefer_deterministic_routing() -> None:
    recipes = _load_recipe_map()
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    intent = json.loads(Path("templates/authorization/no_admin_route_bypass.intent.json").read_text(encoding="utf-8"))

    prefer_budget = budget_from_policy(recipes["Deterministic-only CI"])
    assert prefer_budget.prefer_deterministic is True
    prefer_decision = route_intent(intent, registry.all(), budget=prefer_budget)
    prefer_top = prefer_decision["selected"][0]["backend"]

    formal_budget = budget_from_policy(recipes["Full formal stack"])
    assert formal_budget.prefer_deterministic is False
    formal_decision = route_intent(intent, registry.all(), budget=formal_budget)
    formal_top = formal_decision["selected"][0]["backend"]

    assert prefer_top in {"opa", "z3", "deterministic"}
    assert prefer_decision["selected"][0]["score"] > formal_decision["selected"][0]["score"] or prefer_top != formal_top
    prefer_scores = {item["backend"]: item["score"] for item in prefer_decision["selected"]}
    formal_scores = {item["backend"]: item["score"] for item in formal_decision["selected"]}
    for backend in {"opa", "z3"}:
        if backend in prefer_scores and backend in formal_scores:
            assert prefer_scores[backend] > formal_scores[backend]
