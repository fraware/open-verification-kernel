"""Governed trusted-bypass authorization evidence and synthetic guards.

Bypass field names never imply authorization. A candidate mechanism requires:

    governed profile mapping
  + proved writer authority (closed-world)
  + bound branch-outcome control point

Only then may a synthetic AuthorizationGuard be emitted. BypassAuthorityFinding
remains diagnostic; BypassAuthorityEvidence is the durable IR form.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ovk.compilers.authorization.authorization_cut_set import (
    evaluate_authorization_cut_set,
)
from ovk.compilers.authorization.bypass_authority import (
    BypassAuthorityFinding,
    ClosedWorldScopeProof,
    analyze_bypass_authority_unit,
    bypass_authority_digest,
)
from ovk.compilers.authorization.handler_control_flow import (
    HandlerControlFlowSummary,
    find_control_flow_edge_ref,
    scoped_control_flow_edge_id_from_local,
)
from ovk.core.assurance_ir import (
    AssuranceIR,
    AuthorizationControlPointEvidence,
    AuthorizationGuard,
    BypassAuthorityEvidence,
    BypassAuthorityEvidenceStatus,
    SemanticOrigin,
)
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_FIELD_KEY_RE = re.compile(r"^request\.state\.([A-Za-z_][A-Za-z0-9_]*)$")


def trusted_bypass_field_name(policy_key: str) -> str | None:
    """Return the request.state field for a governed policy key, else None."""

    match = _FIELD_KEY_RE.fullmatch(policy_key.strip())
    if match is None:
        return None
    return match.group(1)


def closed_world_scope_digest(
    scope_proof: ClosedWorldScopeProof | None,
    *,
    derived_scope_digest: str | None = None,
) -> str | None:
    """Digest for durable bypass evidence.

    Prefer the full ``DerivedClosedWorldScopeProof.digest()`` when available so
    durable evidence retains revision/manifest/import-resolution identity.
    The stripped path/root pair is a fallback for unit fixtures only.
    """

    if derived_scope_digest is not None:
        digest = derived_scope_digest.strip()
        if not digest:
            raise ValueError("derived_scope_digest must be non-empty")
        return digest
    if scope_proof is None:
        return None
    return content_digest(
        {
            "accounted_paths": list(scope_proof.accounted_paths),
            "source_roots": list(scope_proof.source_roots),
        }
    )


def _finding_status(
    finding: BypassAuthorityFinding,
) -> BypassAuthorityEvidenceStatus:
    if finding.status == "authorized":
        return "established"
    if finding.status == "violated":
        return "violated"
    return "unknown"


def _expression_mentions_field(expression: str | None, field_name: str) -> bool:
    if expression is None:
        return False
    needles = (
        f"request.state.{field_name}",
        f"getattr(request.state, '{field_name}'",
        f'getattr(request.state, "{field_name}"',
        field_name,
    )
    return any(needle in expression for needle in needles)


def _branch_is_negated_field_read(expression: str, field_name: str) -> bool:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return expression.strip().startswith("not ") and field_name in expression
    node = tree.body
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _expression_mentions_field(ast.unparse(node.operand), field_name)
    return False


def resolve_bypass_control_point_edge(
    cfg: HandlerControlFlowSummary,
    *,
    field_name: str,
) -> str | None:
    """Resolve the unique authorizing branch-outcome edge for a bypass field.

    ``if <field>`` / ``if request.state.<field>`` → True outcome.
    ``if not <field>`` → False outcome (equivalent to field == True).
    Ambiguous or missing bindings return None.
    """

    matches: list[tuple[str, bool]] = []
    for node in cfg.nodes:
        if node.kind != "branch":
            continue
        expression = node.expression
        if expression is None or not _expression_mentions_field(
            expression, field_name
        ):
            continue
        # Prefer exact field reads over incidental name collisions in larger
        # expressions by requiring request.state.<field> or a bare Name equal
        # to the field / not field.
        exact = (
            f"request.state.{field_name}" in expression
            or expression.strip() == field_name
            or expression.strip() == f"not {field_name}"
            or expression.strip().startswith(f"not request.state.{field_name}")
            or f"getattr(request.state, '{field_name}'" in expression
            or f'getattr(request.state, "{field_name}"' in expression
        )
        if not exact:
            continue
        authorizing_true = not _branch_is_negated_field_read(
            expression, field_name
        )
        matches.append((node.node_id, authorizing_true))

    if len(matches) != 1:
        return None
    branch_id, want_true = matches[0]
    edge = find_control_flow_edge_ref(
        cfg,
        source_node_id=branch_id,
        branch_value=want_true,
    )
    return None if edge is None else edge.edge_id


def build_bypass_authority_evidence(
    finding: BypassAuthorityFinding,
    *,
    read_origin: SemanticOrigin,
    origin: SemanticOrigin,
    control_point_edge_id: str | None = None,
    control_flow_summary_digest: str | None = None,
    entrypoint: str | None = None,
    scope_proof: ClosedWorldScopeProof | None = None,
    derived_scope_digest: str | None = None,
    assumptions: Sequence[str] = (),
) -> BypassAuthorityEvidence:
    """Lift a diagnostic finding into durable BypassAuthorityEvidence."""

    status = _finding_status(finding)
    scope_digest = closed_world_scope_digest(
        scope_proof,
        derived_scope_digest=derived_scope_digest,
    )
    if (
        finding.closed_world is not None
        and finding.closed_world.complete
        and scope_digest is None
    ):
        scope_digest = content_digest(
            {
                "accounted_paths": list(finding.closed_world.accounted_paths),
                "source_roots": list(finding.closed_world.source_roots),
            }
        )

    # Established IR status requires the authorizing edge. Without it, stay
    # unknown even when writers are proved.
    if status == "established" and (
        control_point_edge_id is None
        or control_flow_summary_digest is None
        or entrypoint is None
    ):
        status = "unknown"
        reason = "bypass_control_point_unbound"
    else:
        reason = finding.reason

    return BypassAuthorityEvidence(
        evidence_id=f"bypass:{finding.field_name}:{content_digest({'r': reason, 'e': control_point_edge_id or '', 'c': control_flow_summary_digest or '', 'p': entrypoint or ''})[:12]}",
        field_name=finding.field_name,
        read_expression=finding.read_expression,
        read_origin=read_origin,
        status=status,
        control_point_edge_id=control_point_edge_id,
        control_flow_summary_digest=control_flow_summary_digest,
        entrypoint=entrypoint,
        writer_evidence_ids=list(finding.evidence_ids),
        closed_world_scope_digest=scope_digest,
        assumptions=list(assumptions),
        reason=reason,
        origin=origin,
    )


@dataclass(frozen=True)
class TrustedBypassAuthorizationResult:
    evidence: tuple[BypassAuthorityEvidence, ...]
    guards: tuple[AuthorizationGuard, ...]
    control_points: tuple[AuthorizationControlPointEvidence, ...] = ()


def synthesize_trusted_bypass_guard(
    *,
    evidence: BypassAuthorityEvidence,
    principal_id: str,
    effect_id: str,
    resource_id: str,
    origin: SemanticOrigin,
) -> AuthorizationGuard | None:
    """Emit a synthetic guard only when evidence is fully established."""

    if evidence.status != "established":
        return None
    if evidence.control_point_edge_id is None:
        return None
    if evidence.control_flow_summary_digest is None:
        return None
    if evidence.entrypoint is None:
        return None
    if not evidence.writer_evidence_ids:
        return None
    if evidence.closed_world_scope_digest is None:
        return None
    return AuthorizationGuard(
        guard_id=(
            f"guard:trusted_bypass:{evidence.field_name}:"
            f"{effect_id}:{content_digest(evidence.control_point_edge_id)[:10]}"
        ),
        principal_id=principal_id,
        effect_id=effect_id,
        resource_id=resource_id,
        effectiveness="established",
        effectiveness_evidence_ids=[evidence.evidence_id],
        condition_ids=[evidence.control_point_edge_id],
        origin=origin,
    )


def build_authorization_control_point_evidence(
    *,
    guard: AuthorizationGuard,
    protected_effect_id: str,
    evidence: BypassAuthorityEvidence,
    origin: SemanticOrigin,
) -> AuthorizationControlPointEvidence | None:
    """Bind a synthetic bypass guard to an exact CFG control point."""

    if (
        evidence.status != "established"
        or evidence.control_point_edge_id is None
        or evidence.control_flow_summary_digest is None
        or evidence.entrypoint is None
    ):
        return None
    scoped = scoped_control_flow_edge_id_from_local(
        control_flow_summary_digest=evidence.control_flow_summary_digest,
        entrypoint=evidence.entrypoint,
        local_edge_id=evidence.control_point_edge_id,
    )
    return AuthorizationControlPointEvidence(
        evidence_id=(
            f"acp:{guard.guard_id}:{content_digest(scoped)[:12]}"
        ),
        guard_id=guard.guard_id,
        protected_effect_id=protected_effect_id,
        principal_id=guard.principal_id,
        effect_id=guard.effect_id,
        resource_id=guard.resource_id,
        entrypoint=evidence.entrypoint,
        control_flow_summary_digest=evidence.control_flow_summary_digest,
        edge_id=evidence.control_point_edge_id,
        scoped_edge_id=scoped,
        bypass_evidence_id=evidence.evidence_id,
        origin=origin,
    )


def evaluate_trusted_bypass_authorizations(
    *,
    files: Mapping[str, str],
    entry_path: str,
    function_name: str | None,
    cfg: HandlerControlFlowSummary | None,
    trusted_bypass_authorities: Mapping[str, Sequence[str]],
    principal_id: str,
    effect_bindings: Mapping[str, tuple[str, str]],
    origin: SemanticOrigin,
    scope_proof: ClosedWorldScopeProof | None = None,
    derived_scope_digest: str | None = None,
    entrypoint: str | None = None,
) -> TrustedBypassAuthorizationResult:
    """Analyze governed bypass fields and emit evidence plus synthetic guards.

    ``trusted_bypass_authorities`` maps policy keys such as
    ``request.state.bypass_filter`` to authorized effect names. Name-based
    inference is refused: only explicitly listed keys participate.

    ``effect_bindings`` maps effect name -> ``(effect_id, resource_id)``.
    ``derived_scope_digest`` should be ``DerivedClosedWorldScopeProof.digest()``
    whenever product compile produced a machine-derived scope proof.
    ``entrypoint`` scopes the authorizing control point to one handler.
    """

    field_to_effects: dict[str, tuple[str, ...]] = {}
    for policy_key, effects in trusted_bypass_authorities.items():
        field = trusted_bypass_field_name(policy_key)
        if field is None:
            continue
        normalized = tuple(sorted({effect.strip() for effect in effects if effect.strip()}))
        if not normalized:
            continue
        field_to_effects[field] = normalized

    if not field_to_effects:
        return TrustedBypassAuthorizationResult(evidence=(), guards=())

    findings = analyze_bypass_authority_unit(
        files,
        entry_path=entry_path,
        function_name=function_name,
        bypass_fields=frozenset(field_to_effects),
        scope_proof=scope_proof,
    )

    cfg_digest = cfg.digest() if cfg is not None else None
    resolved_entrypoint = entrypoint or (
        f"{entry_path}:{function_name}" if function_name else entry_path
    )

    evidence_items: list[BypassAuthorityEvidence] = []
    guards: list[AuthorizationGuard] = []
    for finding in findings:
        edge_id = None
        if cfg is not None:
            edge_id = resolve_bypass_control_point_edge(
                cfg,
                field_name=finding.field_name,
            )
        evidence = build_bypass_authority_evidence(
            finding,
            read_origin=origin,
            origin=origin,
            control_point_edge_id=edge_id,
            control_flow_summary_digest=cfg_digest if edge_id is not None else None,
            entrypoint=resolved_entrypoint if edge_id is not None else None,
            scope_proof=scope_proof,
            derived_scope_digest=derived_scope_digest,
            assumptions=(
                "trusted_bypass_requires_profile_mapping",
                "trusted_bypass_requires_proved_writers",
                "trusted_bypass_requires_branch_outcome_control_point",
            ),
        )
        evidence_items.append(evidence)
        if evidence.status != "established":
            continue
        for effect_name in field_to_effects.get(finding.field_name, ()):
            binding = effect_bindings.get(effect_name)
            if binding is None:
                continue
            effect_id, resource_id = binding
            guard = synthesize_trusted_bypass_guard(
                evidence=evidence,
                principal_id=principal_id,
                effect_id=effect_id,
                resource_id=resource_id,
                origin=origin,
            )
            if guard is not None:
                guards.append(guard)

    return TrustedBypassAuthorizationResult(
        evidence=tuple(evidence_items),
        guards=tuple(guards),
    )


def effect_bindings_from_ir(ir: AssuranceIR) -> dict[str, tuple[str, str]]:
    """Map effect name -> (effect_id, acted resource_id)."""

    effect_names = {item.effect_id: item.name for item in ir.effects}
    mapping: dict[str, tuple[str, str]] = {}
    for protected in ir.protected_effects:
        name = effect_names.get(protected.effect_id)
        if name is None:
            continue
        mapping.setdefault(name, (protected.effect_id, protected.resource_id))
    return mapping


_REPO_CLOSURE_IMPORT_STATUSES = frozenset(
    {
        "authenticated_revision_python_manifest_v1",
        "authenticated_revision_python_manifest_v2",
        "authenticated_revision_python_manifest_v3",
        "unit_local_static_imports_v1",
    }
)


def enrich_assurance_ir_with_trusted_bypass(
    ir: AssuranceIR,
    *,
    materials: Mapping[str, str],
    trusted_bypass_authorities: Mapping[str, Sequence[str]],
    route_cfgs: Mapping[tuple[str, str], HandlerControlFlowSummary | None],
    principal_id: str,
    scope_proof: ClosedWorldScopeProof | None = None,
    derived_scope_digest: str | None = None,
    import_resolution_status: str | None = None,
) -> AssuranceIR:
    """Attach bypass-authority evidence and synthetic guards to an assembled IR.

    Without a closed-world scope proof, established status is refused (Unknown >
    false PASS). Empty profile mapping yields no enrichment.

    Established synthetic guards are attached to matching semantic paths and
    their authorizing edges are merged into existing cut-set evidence. Cover is
    re-evaluated against the handler CFG when an edge is added so a body-node
    cut plus a proved bypass edge can jointly cover. Synthetic bypass guards
    are not inserted into cut ``guard_ids`` (exact identity of body members is
    preserved); PE qualifies edge members via BypassAuthorityEvidence.
    """

    if not trusted_bypass_authorities:
        return ir

    # Sparse / workspace materials are not repository closed-world. Refuse
    # established bypass so PE cannot false-PASS on incomplete closure.
    refuse_established = (
        import_resolution_status is not None
        and import_resolution_status not in _REPO_CLOSURE_IMPORT_STATUSES
    )

    effect_bindings = effect_bindings_from_ir(ir)
    evidence_by_id = {
        item.evidence_id: item for item in ir.bypass_authority_evidence
    }
    guards_by_id = {item.guard_id: item for item in ir.guards}
    emitted_guards: list[AuthorizationGuard] = []

    cfg_by_digest = {
        cfg.digest(): cfg
        for cfg in route_cfgs.values()
        if cfg is not None
    }

    control_points_by_id: dict[str, AuthorizationControlPointEvidence] = {
        item.evidence_id: item for item in ir.authorization_control_point_evidence
    }
    # Track which handler (path, function) emitted each guard so path/cut
    # attachment cannot cross handlers via colliding local edge ids.
    guard_emission_scope: dict[str, tuple[str | None, str | None, str]] = {}

    for (path, function_name), cfg in sorted(route_cfgs.items()):
        if path not in materials:
            continue
        origin = read_origin_for_path(path)
        cfg_digest = cfg.digest() if cfg is not None else None
        # Prefer HTTP entrypoints already present on cuts/paths for this CFG.
        http_entrypoints = sorted(
            {
                item.entrypoint
                for item in ir.authorization_cut_set_evidence
                if item.control_flow_summary_digest == cfg_digest
                and item.entrypoint
            }
            | {
                item.entrypoint
                for item in ir.paths
                if item.entrypoint and cfg_digest is not None
            }
        )
        entrypoint = (
            http_entrypoints[0]
            if len(http_entrypoints) == 1
            else (
                f"{path}:{function_name}"
                if function_name
                else path
            )
        )
        result = evaluate_trusted_bypass_authorizations(
            files=materials,
            entry_path=path,
            function_name=function_name,
            cfg=cfg,
            trusted_bypass_authorities=trusted_bypass_authorities,
            principal_id=principal_id,
            effect_bindings=effect_bindings,
            origin=origin,
            scope_proof=scope_proof,
            derived_scope_digest=derived_scope_digest,
            entrypoint=entrypoint,
        )
        for evidence in result.evidence:
            if refuse_established and evidence.status == "established":
                evidence.status = "unknown"
                evidence.reason = "sparse_or_workspace_scope_not_repo_closure"
                evidence.control_flow_summary_digest = None
                evidence.entrypoint = None
            evidence_by_id[evidence.evidence_id] = evidence
        for guard in result.guards:
            if refuse_established:
                continue
            guards_by_id[guard.guard_id] = guard
            emitted_guards.append(guard)
            guard_emission_scope[guard.guard_id] = (
                cfg_digest,
                (
                    evidence_by_id[guard.effectiveness_evidence_ids[0]].entrypoint
                    if guard.effectiveness_evidence_ids
                    and guard.effectiveness_evidence_ids[0] in evidence_by_id
                    else entrypoint
                ),
                path,
            )

    ir.bypass_authority_evidence = sorted(
        evidence_by_id.values(),
        key=lambda item: item.evidence_id,
    )
    ir.guards = sorted(guards_by_id.values(), key=lambda item: item.guard_id)

    if not emitted_guards:
        ir.authorization_control_point_evidence = sorted(
            control_points_by_id.values(),
            key=lambda item: item.evidence_id,
        )
        return ir

    effect_ids_by_protected = {
        item.protected_effect_id: item.effect_id for item in ir.protected_effects
    }
    for semantic_path in ir.paths:
        path_effect_ids = {
            effect_ids_by_protected[pe_id]
            for pe_id in semantic_path.protected_effect_ids
            if pe_id in effect_ids_by_protected
        }
        for guard in emitted_guards:
            if guard.effect_id not in path_effect_ids:
                continue
            scope = guard_emission_scope.get(guard.guard_id)
            if scope is None:
                continue
            cfg_digest, _bypass_entrypoint, _source_path = scope
            if guard.guard_id in semantic_path.guard_ids:
                continue
            path_pe_ids = set(semantic_path.protected_effect_ids)
            shares_cfg = any(
                cut.protected_effect_id in path_pe_ids
                and cut.control_flow_summary_digest == cfg_digest
                for cut in ir.authorization_cut_set_evidence
            )
            if cfg_digest is not None and not shares_cfg:
                continue
            semantic_path.guard_ids = sorted(
                [*semantic_path.guard_ids, guard.guard_id]
            )

    cut_by_id = {
        item.evidence_id: item for item in ir.authorization_cut_set_evidence
    }
    for guard in emitted_guards:
        if not guard.effectiveness_evidence_ids:
            continue
        bypass = evidence_by_id.get(guard.effectiveness_evidence_ids[0])
        if bypass is None or bypass.status != "established":
            continue
        edge_id = bypass.control_point_edge_id
        cfg_digest = bypass.control_flow_summary_digest
        if edge_id is None or cfg_digest is None:
            continue
        scope = guard_emission_scope.get(guard.guard_id)
        origin = guard.origin
        for protected in ir.protected_effects:
            if protected.effect_id != guard.effect_id:
                continue
            if protected.resource_id != guard.resource_id:
                continue
            matching = [
                item
                for item in cut_by_id.values()
                if item.protected_effect_id == protected.protected_effect_id
                and item.control_flow_summary_digest == cfg_digest
            ]
            for cut in matching:
                # Merge the authorizing edge into structural cut points only
                # under the same CFG digest (no cross-handler local-id merge).
                if edge_id not in cut.edge_control_points:
                    cut.edge_control_points = sorted(
                        [*cut.edge_control_points, edge_id]
                    )
                control_point = build_authorization_control_point_evidence(
                    guard=guard,
                    protected_effect_id=protected.protected_effect_id,
                    evidence=bypass,
                    origin=origin,
                )
                if control_point is not None:
                    control_points_by_id[control_point.evidence_id] = control_point
                if cut.unresolved_guard_ids:
                    continue
                if cut.effect_cfg_node_id is None:
                    continue
                cfg = cfg_by_digest.get(cfg_digest)
                if cfg is None:
                    continue
                cut_nodes = frozenset(
                    cut.node_control_points
                    or list(cut.guard_cfg_node_ids.values())
                )
                cut_edges = frozenset(cut.edge_control_points)
                result = evaluate_authorization_cut_set(
                    cfg,
                    sink_node_id=cut.effect_cfg_node_id,
                    cut_node_ids=cut_nodes,
                    cut_edge_ids=cut_edges,
                )
                cut.covers_all_paths = result.covers_all_paths
                cut.coverage_status = result.coverage_status
                cut.reason = result.reason
                if (
                    result.coverage_status == "complete"
                    and not result.covers_all_paths
                ):
                    cut.uncovered_path_node_ids = list(
                        result.uncovered_path_node_ids
                    )
                else:
                    cut.uncovered_path_node_ids = []
    ir.authorization_cut_set_evidence = sorted(
        cut_by_id.values(),
        key=lambda item: item.evidence_id,
    )
    ir.authorization_control_point_evidence = sorted(
        control_points_by_id.values(),
        key=lambda item: item.evidence_id,
    )
    return ir


def trusted_bypass_findings_digest(
    findings: tuple[BypassAuthorityFinding, ...],
) -> str:
    """Stable digest helper for tests and cache invalidation."""

    return bypass_authority_digest(findings)


def read_origin_for_path(path: str, line: int | None = None) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="assurance.fastapi.trusted_bypass.ast_v1",
        extractor_version="0.1.0",
        source_range=(
            None
            if line is None
            else SourceRange(path=path, start_line=line, end_line=line)
        ),
    )
