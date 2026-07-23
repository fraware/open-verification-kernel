"""CBMC project model and honest guarantee typing.

Only ``bounded_project_model_check`` implies project code is included in the
model. Weaker guarantees must not be renamed to imply project coverage.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

CbmcGuaranteeType = Literal[
    "bounded_project_model_check",
    "bounded_harness_model_check",
    "syntax_contract_check",
    "compile_database_resolution",
]


class CbmcFunctionTarget(BaseModel):
    name: str
    file: str | None = None
    selected_reason: str


class CbmcHarness(BaseModel):
    harness_id: str
    entry_function: str
    source_path: str | None = None
    # Traceability fields
    traces_to_obligation_id: str | None = None
    traces_to_intent_id: str | None = None
    traces_to_source_functions: list[str] = Field(default_factory=list)
    bound: int | None = None
    includes_project_code: bool = False


class CbmcProject(BaseModel):
    schema_version: Literal["ovk.cbmc.project.v1"] = "ovk.cbmc.project.v1"
    compile_commands_path: str | None = None
    source_roots: list[str] = Field(default_factory=list)
    functions: list[CbmcFunctionTarget] = Field(default_factory=list)
    harnesses: list[CbmcHarness] = Field(default_factory=list)
    environment_models: list[str] = Field(default_factory=list)
    guarantee_type: CbmcGuaranteeType = "syntax_contract_check"
    warnings: list[str] = Field(default_factory=list)

    def declare_guarantee(self) -> CbmcGuaranteeType:
        """Honest guarantee naming based on what is actually modeled."""
        if any(harness.includes_project_code for harness in self.harnesses) and self.functions:
            return "bounded_project_model_check"
        if self.harnesses:
            return "bounded_harness_model_check"
        if self.compile_commands_path:
            return "compile_database_resolution"
        return "syntax_contract_check"


def guarantee_implies_project_code(guarantee: CbmcGuaranteeType) -> bool:
    return guarantee == "bounded_project_model_check"
