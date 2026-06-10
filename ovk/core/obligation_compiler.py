"""Registry mapping intents and changes to lane obligations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.core.context import RepositoryContext
from ovk.core.lane_compiler import INTENT_TO_LANE, compile_lane_inputs_from_plan


class ObligationCompilerRegistry:
    """Maps `(intent, change, context)` to executable lane obligations."""

    def __init__(self, intent_to_lane: dict[str, str] | None = None) -> None:
        self._intent_to_lane = intent_to_lane or dict(INTENT_TO_LANE)

    @classmethod
    def default(cls) -> "ObligationCompilerRegistry":
        return cls()

    def lane_for_intent(self, intent_id: str) -> str | None:
        return self._intent_to_lane.get(intent_id)

    def compile(
        self,
        plan: dict[str, Any],
        *,
        context: RepositoryContext,
        diff_text: str | None = None,
        metadata: dict[str, Any] | None = None,
        check_metadata_path: Path | None = None,
        github_event_path: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Compile obligations (lane jobs) from a plan and repository context."""
        meta = dict(metadata or {})
        meta.setdefault("changed_files", context.changed_files)
        meta.setdefault("actor_type", context.actor_type)
        meta.update(context.branch_metadata)

        jobs = compile_lane_inputs_from_plan(
            plan,
            diff_text=diff_text,
            metadata=meta,
            check_metadata_path=check_metadata_path,
            github_event_path=github_event_path,
        )
        obligations: list[dict[str, Any]] = []
        for job in jobs:
            lane = str(job["lane"])
            intent_id = next((intent for intent, mapped in self._intent_to_lane.items() if mapped == lane), lane)
            obligations.append(
                {
                    "intent_id": intent_id,
                    "lane": lane,
                    "input": job["data"],
                    "input_format": job.get("input_format", "infra"),
                    "scope": context.changed_files,
                    "repo": context.repo,
                    "head_sha": context.head_sha,
                    "policy_path": job.get("policy_path"),
                    "job_id": job.get("job_id"),
                }
            )
        return obligations


def compile_obligations(
    plan: dict[str, Any],
    *,
    context: RepositoryContext,
    diff_text: str | None = None,
) -> list[dict[str, Any]]:
    """Compile obligations using the default registry."""
    return ObligationCompilerRegistry.default().compile(plan, context=context, diff_text=diff_text)
