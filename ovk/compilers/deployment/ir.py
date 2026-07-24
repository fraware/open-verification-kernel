"""Deployment intermediate representation and guarantee naming."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

DeploymentSource = Literal["explicit_schema", "github_environments", "argo_rollouts", "unknown"]


class DeploymentState(BaseModel):
    name: str
    kind: Literal["draft", "review", "approved", "deployed", "failed", "custom"] = "custom"
    production: bool = False
    required: bool = False


class DeploymentTransition(BaseModel):
    source: str
    target: str
    label: str | None = None


class DeploymentIR(BaseModel):
    schema_version: Literal["ovk.deployment.ir.v1"] = "ovk.deployment.ir.v1"
    source: DeploymentSource = "unknown"
    initial_state: str | None = None
    states: list[DeploymentState] = Field(default_factory=list)
    transitions: list[DeploymentTransition] = Field(default_factory=list)
    required_states: list[str] = Field(default_factory=list)
    production_states: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    unsupported_constructs: list[str] = Field(default_factory=list)

    def to_lane_input(self) -> dict[str, Any]:
        return {
            "initial_state": self.initial_state,
            "states": [item.name for item in self.states],
            "transitions": [{"from": item.source, "to": item.target, "label": item.label} for item in self.transitions],
            "required_states": list(self.required_states),
            "production_states": list(self.production_states),
            "warnings": list(self.warnings),
        }
