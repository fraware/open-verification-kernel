"""GitHub Actions trust-flow intermediate representation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

TrustFindingKind = Literal[
    "untrusted_code_with_secret",
    "untrusted_code_with_write_token",
    "untrusted_code_with_protected_env",
    "untrusted_code_with_privileged_capability",
    "mutable_remote_ref",
    "secrets_inherit",
    "cycle",
    "review",
]


class WorkflowRef(BaseModel):
    path: str
    remote: bool = False
    owner_repo: str | None = None
    ref: str | None = None
    digest: str | None = None
    mutable_ref: bool = False


class SecretUse(BaseModel):
    name: str
    job_id: str | None = None
    step_id: str | None = None
    expression: str


class PermissionGrant(BaseModel):
    scope: str
    level: str
    job_id: str | None = None


class TrustNode(BaseModel):
    node_id: str
    kind: str
    trust: Literal["trusted", "untrusted", "unknown"] = "unknown"
    labels: list[str] = Field(default_factory=list)


class TrustEdge(BaseModel):
    source: str
    target: str
    kind: str


class TrustFinding(BaseModel):
    kind: TrustFindingKind
    summary: str
    node_ids: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class GitHubActionsIR(BaseModel):
    schema_version: Literal["ovk.github_actions.ir.v1"] = "ovk.github_actions.ir.v1"
    workflows: list[WorkflowRef] = Field(default_factory=list)
    nodes: list[TrustNode] = Field(default_factory=list)
    edges: list[TrustEdge] = Field(default_factory=list)
    secrets: list[SecretUse] = Field(default_factory=list)
    permissions: list[PermissionGrant] = Field(default_factory=list)
    findings: list[TrustFinding] = Field(default_factory=list)
    unsupported_constructs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
