from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi import (
    FastApiProtectedEffectExtractor,
    ProtectedEffectProfile,
)
from ovk.core.protected_effect_integrity import compile_protected_effect_integrity


PROFILE = ProtectedEffectProfile(
    sink_effects={"issue_refund": "billing.invoice.refund"},
    principal_parameter="user",
    guard_functions=frozenset({"authorize"}),
    resource_loader_identity_args={"load_invoice": 0},
)


def _compile(source: str):
    materials = materials_from_pair(
        path="app.py",
        base_source=source,
        head_source=source,
        repo="example/payments",
        base_revision="a",
        head_revision="b",
    )
    return FastApiProtectedEffectExtractor().compile(materials, PROFILE)


def _resource_status(ir) -> str:
    obligation = compile_protected_effect_integrity(ir)[0]
    return next(check.status for check in obligation.checks if check.dimension == "resource_binding")


def test_same_resource_guard_and_sink_are_structurally_established() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/invoices/{invoice_id}/refund")
def refund(invoice_id: str, user):
    invoice = load_invoice(invoice_id)
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
""".strip()

    ir = _compile(source)

    assert ir.coverage.status == "complete"
    assert len(ir.protected_effects) == 1
    assert len(ir.guards) == 1
    assert ir.resource_bindings == []
    assert _resource_status(ir) == "established"


def test_distinct_authorized_and_acted_resources_emit_binding_obligation() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/invoices/{invoice_id}/refund")
def refund(invoice_id: str, user, other_invoice_id: str):
    invoice = load_invoice(invoice_id)
    other_invoice = load_invoice(other_invoice_id)
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(other_invoice)
""".strip()

    ir = _compile(source)

    assert ir.coverage.status == "complete"
    assert len(ir.resource_bindings) == 1
    binding = ir.resource_bindings[0]
    assert binding.authorized_resource_id != binding.acted_resource_id
    assert binding.relation == "equal"
    assert _resource_status(ir) == "unknown"


def test_missing_guard_is_a_structural_violation() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/invoices/{invoice_id}/refund")
def refund(invoice_id: str, user):
    invoice = load_invoice(invoice_id)
    issue_refund(invoice)
""".strip()

    ir = _compile(source)
    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "violated"
    guard_check = next(check for check in obligation.checks if check.dimension == "guard_presence")
    assert guard_check.status == "violated"


def test_control_flow_marks_profile_partial() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/invoices/{invoice_id}/refund")
def refund(invoice_id: str, user, enabled: bool):
    invoice = load_invoice(invoice_id)
    if enabled:
        authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
""".strip()

    ir = _compile(source)

    assert ir.coverage.status == "partial"
    assert any("control_flow_outside_v1_subset" in item for item in ir.coverage.unsupported_constructs)


def test_dynamic_guard_effect_marks_profile_partial_and_does_not_mint_guard() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/invoices/{invoice_id}/refund")
def refund(invoice_id: str, user, action: str):
    invoice = load_invoice(invoice_id)
    authorize(user, action, invoice)
    issue_refund(invoice)
""".strip()

    ir = _compile(source)

    assert ir.coverage.status == "partial"
    assert len(ir.guards) == 0
    assert any("dynamic_guard_effect" in item for item in ir.coverage.unsupported_constructs)



def test_declared_loader_projects_resource_identity_from_key() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/invoices/{invoice_id}/refund")
def refund(invoice_id: str, user):
    invoice = load_invoice(invoice_id)
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
""".strip()

    ir = _compile(source)
    invoice = next(resource for resource in ir.resources if resource.symbol == "invoice")

    assert invoice.identity_term is not None
    assert invoice.identity_term.kind == "symbol"
    assert invoice.identity_term.value == "invoice_id"


def test_distinct_loader_keys_are_preserved_as_distinct_identity_terms() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/invoices/{invoice_id}/refund")
def refund(invoice_id: str, user, other_invoice_id: str):
    invoice = load_invoice(invoice_id)
    other_invoice = load_invoice(other_invoice_id)
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(other_invoice)
""".strip()

    ir = _compile(source)
    by_symbol = {resource.symbol: resource for resource in ir.resources}

    assert by_symbol["invoice"].identity_term is not None
    assert by_symbol["other_invoice"].identity_term is not None
    assert by_symbol["invoice"].identity_term.value == "invoice_id"
    assert by_symbol["other_invoice"].identity_term.value == "other_invoice_id"



def test_scoped_loader_projects_workspace_scope() -> None:
    profile = ProtectedEffectProfile(
        sink_effects={"read_agent": "workspace.agent.read"},
        guard_functions=frozenset({"authorize_workspace"}),
        resource_loader_identity_args={"load_agent_in_workspace": 1},
        resource_loader_scope_args={"load_agent_in_workspace": 0},
        sink_binding_relations={"read_agent": "same_tenant"},
        sink_acted_projections={"read_agent": "scope"},
    )
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
def get_agent(workspace_id: str, agent_id: str, user):
    authorize_workspace(user, "workspace.agent.read", workspace_id)
    agent = load_agent_in_workspace(workspace_id, agent_id)
    read_agent(agent)
""".strip()
    materials = materials_from_pair(
        path="app.py",
        base_source=source,
        head_source=source,
        repo="example/workspaces",
        base_revision="a",
        head_revision="b",
    )

    ir = FastApiProtectedEffectExtractor().compile(materials, profile)

    agent = next(resource for resource in ir.resources if resource.symbol == "agent")
    assert agent.identity_term is not None
    assert agent.identity_term.value == "agent_id"
    assert agent.scope_term is not None
    assert agent.scope_term.value == "workspace_id"
    binding = ir.resource_bindings[0]
    assert binding.relation == "same_tenant"
    assert binding.authorized_projection == "identity"
    assert binding.acted_projection == "scope"


def test_unscoped_loader_gets_explicit_unconstrained_scope() -> None:
    profile = ProtectedEffectProfile(
        sink_effects={"read_agent": "workspace.agent.read"},
        guard_functions=frozenset({"authorize_workspace"}),
        resource_loader_identity_args={"load_agent": 0},
        resource_loader_unconstrained_scopes=frozenset({"load_agent"}),
        sink_binding_relations={"read_agent": "same_tenant"},
        sink_acted_projections={"read_agent": "scope"},
    )
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
def get_agent(workspace_id: str, agent_id: str, user):
    authorize_workspace(user, "workspace.agent.read", workspace_id)
    agent = load_agent(agent_id)
    read_agent(agent)
""".strip()
    materials = materials_from_pair(
        path="app.py",
        base_source=source,
        head_source=source,
        repo="example/workspaces",
        base_revision="a",
        head_revision="b",
    )

    ir = FastApiProtectedEffectExtractor().compile(materials, profile)

    agent = next(resource for resource in ir.resources if resource.symbol == "agent")
    assert agent.scope_term is not None
    assert agent.scope_term.kind == "symbol"
    assert agent.scope_term.value == "$scope:agent"
    binding = ir.resource_bindings[0]
    assert binding.relation == "same_tenant"
