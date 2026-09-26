from __future__ import annotations

from copy import deepcopy

from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    ContractUse,
    FunctionContract,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.contract_impact import (
    compute_contract_delta_impact,
    compute_contract_impact,
    diff_function_contracts,
)
from ovk.core.models import VerificationSubject


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.contracts",
        extractor_version="0.1.0",
    )


def _contract(
    name: str,
    contract_id: str,
    *,
    depends_on: list[str] | None = None,
    derivation: str = "direct",
) -> FunctionContract:
    return FunctionContract(
        contract_id=contract_id,
        qualified_name=name,
        derivation=derivation,
        depends_on=depends_on or [],
        origin=_origin(f"{name}.py"),
    )


def _ir() -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/app",
            base_sha="a",
            head_sha="b",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.extractor",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(status="complete", confidence=1.0),
        function_contracts=[
            _contract("AgentRepository.get", "c:repo"),
            _contract(
                "AgentService.get",
                "c:service",
                depends_on=["AgentRepository.get"],
                derivation="composed",
            ),
            _contract(
                "AgentFacade.get",
                "c:facade",
                depends_on=["AgentService.get"],
                derivation="composed",
            ),
            _contract("AuditService.record", "c:audit"),
        ],
        contract_uses=[
            ContractUse(
                use_id="use:agent",
                contract_id="c:service",
                qualified_name="AgentService.get",
                resource_id="resource:agent",
                established_attributes=["workspace_id"],
                origin=_origin("routes/agents.py"),
            ),
            ContractUse(
                use_id="use:audit",
                contract_id="c:audit",
                qualified_name="AuditService.record",
                resource_id="resource:audit",
                established_attributes=[],
                origin=_origin("routes/audit.py"),
            ),
        ],
        paths=[
            SemanticPath(
                path_id="path:agent",
                entrypoint="GET /agents/{agent_id}",
                protected_effect_ids=["effect:agent-read"],
                binding_ids=["binding:agent-workspace"],
                contract_use_ids=["use:agent"],
            ),
            SemanticPath(
                path_id="path:audit",
                entrypoint="POST /audit",
                protected_effect_ids=["effect:audit-write"],
                binding_ids=["binding:audit"],
                contract_use_ids=["use:audit"],
            ),
        ],
    )


def test_low_level_contract_change_reaches_transitive_consumers_only() -> None:
    impact = compute_contract_impact(_ir(), ["AgentRepository.get"])

    assert impact.affected_contracts == [
        "AgentFacade.get",
        "AgentRepository.get",
        "AgentService.get",
    ]
    assert impact.affected_contract_uses == ["use:agent"]
    assert impact.affected_paths == ["path:agent"]
    assert impact.affected_protected_effects == ["effect:agent-read"]
    assert impact.affected_bindings == ["binding:agent-workspace"]
    assert "AuditService.record" not in impact.affected_contracts
    assert "effect:audit-write" not in impact.affected_protected_effects


def test_middle_contract_change_reaches_facade_and_its_uses() -> None:
    impact = compute_contract_impact(_ir(), ["AgentService.get"])

    assert impact.affected_contracts == [
        "AgentFacade.get",
        "AgentService.get",
    ]
    assert impact.affected_contract_uses == ["use:agent"]
    assert impact.affected_protected_effects == ["effect:agent-read"]


def test_unknown_seed_is_explicit_and_does_not_expand() -> None:
    impact = compute_contract_impact(_ir(), ["MissingService.get"])

    assert impact.seed_contracts == ["MissingService.get"]
    assert impact.unresolved_seeds == ["MissingService.get"]
    assert impact.affected_contracts == []
    assert impact.affected_contract_uses == []
    assert impact.affected_protected_effects == []


def test_contract_delta_detects_added_removed_and_version_changed() -> None:
    base = _ir()
    head = deepcopy(base)

    head.function_contracts = [
        contract
        for contract in head.function_contracts
        if contract.qualified_name != "AuditService.record"
    ]
    head.function_contracts.append(
        _contract("BillingService.charge", "c:billing")
    )
    repo = next(
        contract
        for contract in head.function_contracts
        if contract.qualified_name == "AgentRepository.get"
    )
    repo.contract_id = "c:repo:v2"

    delta = diff_function_contracts(base, head)

    assert delta.added == ["BillingService.charge"]
    assert delta.removed == ["AuditService.record"]
    assert delta.version_changed == ["AgentRepository.get"]
    assert delta.changed_contracts == [
        "AgentRepository.get",
        "AuditService.record",
        "BillingService.charge",
    ]


def test_delta_impact_uses_both_revisions_for_removed_contracts() -> None:
    base = _ir()
    head = deepcopy(base)

    # Removing the audit contract and its call site makes it absent from head,
    # but the delta must still report the base protected surface it invalidated.
    head.function_contracts = [
        contract
        for contract in head.function_contracts
        if contract.qualified_name != "AuditService.record"
    ]
    head.contract_uses = [
        use for use in head.contract_uses if use.qualified_name != "AuditService.record"
    ]
    head.paths = [path for path in head.paths if path.path_id != "path:audit"]

    impact = compute_contract_delta_impact(base, head)

    assert impact.delta.removed == ["AuditService.record"]
    assert "AuditService.record" in impact.base.affected_contracts
    assert "AuditService.record" in impact.head.unresolved_seeds
    assert "effect:audit-write" in impact.affected_protected_effects
    assert "path:audit" in impact.affected_paths


def test_version_change_propagates_through_composed_contract_graph() -> None:
    base = _ir()
    head = deepcopy(base)

    repo = next(
        contract
        for contract in head.function_contracts
        if contract.qualified_name == "AgentRepository.get"
    )
    service = next(
        contract
        for contract in head.function_contracts
        if contract.qualified_name == "AgentService.get"
    )
    facade = next(
        contract
        for contract in head.function_contracts
        if contract.qualified_name == "AgentFacade.get"
    )

    repo.contract_id = "c:repo:v2"
    # In the real inference pipeline composed IDs change when their callee
    # contract changes; model that expected semantic propagation here.
    service.contract_id = "c:service:v2"
    facade.contract_id = "c:facade:v2"

    impact = compute_contract_delta_impact(base, head)

    assert impact.delta.version_changed == [
        "AgentFacade.get",
        "AgentRepository.get",
        "AgentService.get",
    ]
    assert impact.affected_contracts == [
        "AgentFacade.get",
        "AgentRepository.get",
        "AgentService.get",
    ]
    assert impact.affected_contract_uses == ["use:agent"]
    assert impact.affected_protected_effects == ["effect:agent-read"]
