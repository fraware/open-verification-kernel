"""Explicit fallback authorization contract.

Fallback is a security-sensitive substitution of one evidence proposition for
another. Authorization therefore names the complete tuple. Broad booleans or
independent backend/guarantee allowlists are not sufficient for enforced mode.

Cross-backend fallback execution is intentionally *not* enabled merely by this
parser. Until the executor records and validates the primary failure attempt and
the exact fallback attempt as one tuple, enforced routing must keep legacy
``allow_fallback`` disabled.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from ovk.core.bundle import content_digest

AllowedFallbackCause = Literal[
    "tool_unavailable",
    "timeout",
    "resource_exhausted",
    "tool_error",
    "invalid_output",
]

# Post-execution failures are intentionally forbidden for initial strict rules.
# They can be revisited only with a separately justified semantic contract.
STRICT_PREEXECUTION_CAUSES: frozenset[str] = frozenset({"tool_unavailable"})


class FallbackAuthorizationRule(BaseModel):
    """Stable identity for one exact authorized evidence substitution.

    Strict execution remains disabled until the executor records primary attempt,
    cause, rule id, fallback obligation, fallback attempt, and result as one tuple.
    """

    rule_id: str | None = None
    primary_backend: str
    primary_guarantee: str
    fallback_backend: str
    fallback_guarantee: str
    allowed_causes: list[AllowedFallbackCause] = Field(default_factory=list)
    requires_independent_attempt: bool = True
    proposition_id: str | None = None
    profile_id: str | None = None
    proof_relation: Literal["equivalent", "subsumes", "review-only"] = "review-only"

    @model_validator(mode="after")
    def _nonempty(self) -> "FallbackAuthorizationRule":
        for name in (
            "primary_backend",
            "primary_guarantee",
            "fallback_backend",
            "fallback_guarantee",
        ):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} must be non-empty")
        if not self.allowed_causes:
            raise ValueError("allowed_causes must be non-empty")
        if self.primary_backend == self.fallback_backend and self.primary_guarantee == self.fallback_guarantee:
            raise ValueError("fallback rule must substitute a different backend or guarantee")
        if not self.rule_id:
            object.__setattr__(
                self,
                "rule_id",
                "fallback-"
                + content_digest(
                    {
                        "primary_backend": self.primary_backend,
                        "primary_guarantee": self.primary_guarantee,
                        "fallback_backend": self.fallback_backend,
                        "fallback_guarantee": self.fallback_guarantee,
                        "allowed_causes": list(self.allowed_causes),
                        "proposition_id": self.proposition_id,
                        "profile_id": self.profile_id,
                        "proof_relation": self.proof_relation,
                    }
                )[:16],
            )
        return self

    def authorizes(
        self,
        *,
        primary_backend: str,
        primary_guarantee: str,
        fallback_backend: str,
        fallback_guarantee: str,
        cause: str,
    ) -> bool:
        return (
            self.primary_backend == primary_backend
            and self.primary_guarantee == primary_guarantee
            and self.fallback_backend == fallback_backend
            and self.fallback_guarantee == fallback_guarantee
            and cause in set(self.allowed_causes)
        )


FallbackRule = FallbackAuthorizationRule


def fallback_rules_from_policy(policy: dict[str, Any] | None) -> list[FallbackRule]:
    """Parse explicit rules from ``routing.fallback_rules`` fail-closed."""
    if not isinstance(policy, dict):
        return []
    routing = policy.get("routing")
    if not isinstance(routing, dict):
        return []
    raw = routing.get("fallback_rules")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("routing.fallback_rules must be a list")
    return [FallbackRule.model_validate(item) for item in raw]


def strict_fallback_rules_from_policy(policy: dict[str, Any] | None) -> list[FallbackRule]:
    """Return only rules safe for the initial strict fallback profile.

    The initial profile permits only pre-execution tool unavailability. Timeouts,
    invalid output, resource exhaustion and tool errors occur after an execution
    boundary was crossed and cannot silently authorize a weaker proof.
    """
    rules = fallback_rules_from_policy(policy)
    unsafe = [
        rule
        for rule in rules
        if not set(rule.allowed_causes).issubset(STRICT_PREEXECUTION_CAUSES)
    ]
    if unsafe:
        raise ValueError(
            "enforced fallback rules may currently authorize only tool_unavailable; "
            "post-execution failure fallback remains disabled"
        )
    return rules


def legacy_broad_fallback_requested(policy: dict[str, Any] | None) -> bool:
    if not isinstance(policy, dict):
        return False
    routing = policy.get("routing")
    return bool(isinstance(routing, dict) and routing.get("allow_fallback") is True)
