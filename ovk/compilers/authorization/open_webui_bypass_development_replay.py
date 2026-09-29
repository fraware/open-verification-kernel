"""Open WebUI bypass development-replay report (#125).

This is an explicitly labeled **development replay**. It does not mutate the
frozen round-2 registry and must not be counted as held-out success.

For each pinned revision the report answers, separately:

1. Source extraction succeeded?
2. Bypass predicate represented?
3. Origin established?
4. Ordinary auth guard dominates sink?
5. If not, was bypass path independently authorized?
6. CFG coverage complete?
7. Remaining human-review reason?
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from typing import Any, Literal

from ovk.compilers.authorization.bypass_authority import analyze_bypass_authority
from ovk.compilers.authorization.handler_control_flow import (
    build_handler_control_flow_from_source,
    coverage_authoritative_for,
    dominates as cfg_dominates,
    find_nodes_by_expression_substring,
)
from ovk.compilers.authorization.value_origin import (
    extract_value_origins_from_source,
)
from ovk.core.assurance_ir import ValueOriginEvidence
from ovk.core.bundle import content_digest


OPEN_WEBUI_VULNERABLE_SHA = "30068afd780e034f0c116419103672d7315a7fe3"
OPEN_WEBUI_REPAIR_SHA = "c0385f60ba049da48d2d5452068586d375303c37"

ReplayLabel = Literal["development_replay"]


@dataclass(frozen=True)
class OpenWebUIBypassReplayAnswers:
    source_extraction_succeeded: bool
    bypass_predicate_represented: bool
    origin_established: bool
    ordinary_auth_guard_dominates_sink: bool
    bypass_path_independently_authorized: bool | None
    cfg_coverage_complete: bool
    remaining_human_review_reason: str


@dataclass(frozen=True)
class OpenWebUIBypassReplayRevisionReport:
    revision_sha: str
    label: ReplayLabel
    answers: OpenWebUIBypassReplayAnswers
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class OpenWebUIBypassDevelopmentReplayReport:
    vulnerable: OpenWebUIBypassReplayRevisionReport
    repair: OpenWebUIBypassReplayRevisionReport
    schema_version: Literal["ovk.open_webui_bypass_development_replay.v1"] = (
        "ovk.open_webui_bypass_development_replay.v1"
    )
    label: ReplayLabel = "development_replay"
    held_out_success: Literal[False] = False
    frozen_registry_mutated: Literal[False] = False

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "label": self.label,
            "held_out_success": self.held_out_success,
            "frozen_registry_mutated": self.frozen_registry_mutated,
            "vulnerable": {
                "revision_sha": self.vulnerable.revision_sha,
                "label": self.vulnerable.label,
                "answers": asdict(self.vulnerable.answers),
                "notes": list(self.vulnerable.notes),
            },
            "repair": {
                "revision_sha": self.repair.revision_sha,
                "label": self.repair.label,
                "answers": asdict(self.repair.answers),
                "notes": list(self.repair.notes),
            },
        }

    def digest(self) -> str:
        return content_digest(self.canonical_payload())


def _module_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _select_effect_handler(
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
    *,
    function_name: str | None,
    sink_needle: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    if function_name is not None:
        named = [node for node in functions if node.name == function_name]
        if not named:
            raise ValueError(f"handler function {function_name!r} not found")
        return named[0]

    preferred = [node for node in functions if node.name == "handler"]
    if preferred:
        return preferred[0]

    for node in functions:
        if sink_needle in ast.unparse(node):
            return node

    return functions[0]


def analyze_handler_source_for_bypass_replay(
    source: str,
    *,
    revision_sha: str,
    path: str = "<handler>",
    function_name: str | None = None,
    sink_needle: str = "sink",
    guard_needle: str = "require_access",
    bypass_field: str = "bypass_filter",
) -> OpenWebUIBypassReplayRevisionReport:
    """Analyze one source unit for the multi-question replay report.

    Generic needles keep this helper free of Open WebUI-specific extractor
    identifiers while still supporting pinned Open WebUI development fixtures.
    """

    notes: list[str] = []
    try:
        tree = ast.parse(source)
        functions = _module_functions(tree)
        if not functions:
            raise ValueError("no handler function found")
        handler = _select_effect_handler(
            functions,
            function_name=function_name,
            sink_needle=sink_needle,
        )
        cfg = build_handler_control_flow_from_source(
            source,
            path=path,
            function_name=handler.name,
        )
        # Origins across the whole unit (middleware writes + handler reads).
        origins: list[ValueOriginEvidence] = []
        for fn in functions:
            origins.extend(
                extract_value_origins_from_source(
                    source,
                    path=path,
                    function_name=fn.name,
                )
            )
        bypass_findings = analyze_bypass_authority(
            source,
            path=path,
            function_name=handler.name,
            bypass_fields=frozenset({bypass_field}),
        )
        extraction_ok = True
    except Exception as exc:  # noqa: BLE001 - replay must stay fail-closed
        return OpenWebUIBypassReplayRevisionReport(
            revision_sha=revision_sha,
            label="development_replay",
            answers=OpenWebUIBypassReplayAnswers(
                source_extraction_succeeded=False,
                bypass_predicate_represented=False,
                origin_established=False,
                ordinary_auth_guard_dominates_sink=False,
                bypass_path_independently_authorized=None,
                cfg_coverage_complete=False,
                remaining_human_review_reason=f"extraction_failed:{type(exc).__name__}",
            ),
            notes=(str(exc),),
        )

    bypass_represented = any(
        bypass_field in (item.source_expression or "")
        or item.origin_kind == "request_state_attribute"
        for item in origins
    ) or any(item.field_name == bypass_field for item in bypass_findings)

    origin_kinds = {
        item.origin_kind
        for item in origins
        if bypass_field in (item.source_expression or "")
        or item.origin_kind == "request_state_attribute"
    }
    origin_established = bool(origin_kinds) and "unknown_origin" not in origin_kinds

    sinks = find_nodes_by_expression_substring(cfg, sink_needle)
    guards = find_nodes_by_expression_substring(cfg, guard_needle)
    dominates = False
    cfg_complete = False
    if sinks:
        cfg_complete = all(
            coverage_authoritative_for(cfg, sink.node_id) for sink in sinks
        )
        if guards and cfg_complete:
            dominates = all(
                any(cfg_dominates(cfg, guard.node_id, sink.node_id) for guard in guards)
                for sink in sinks
            )
    else:
        notes.append("sink_not_located_in_cfg")

    authorized: bool | None = None
    bypass_status: str | None = None
    if not dominates:
        matching = [item for item in bypass_findings if item.field_name == bypass_field]
        if matching:
            bypass_status = matching[0].status
            authorized = matching[0].status == "authorized"
            if matching[0].status == "violated":
                notes.append("client_controlled_bypass")
            elif matching[0].status == "unknown":
                notes.append(matching[0].reason)
        else:
            authorized = False
            notes.append("no_bypass_authority_finding")

    if dominates:
        reason = "ordinary_guard_dominates"
    elif authorized:
        reason = "bypass_independently_authorized"
    elif bypass_status == "violated":
        reason = "client_controlled_bypass_not_authorized"
    elif not cfg_complete:
        reason = "cfg_coverage_incomplete"
    elif not origin_established:
        reason = "origin_not_established"
    else:
        reason = "human_review_required"

    return OpenWebUIBypassReplayRevisionReport(
        revision_sha=revision_sha,
        label="development_replay",
        answers=OpenWebUIBypassReplayAnswers(
            source_extraction_succeeded=extraction_ok,
            bypass_predicate_represented=bypass_represented,
            origin_established=origin_established,
            ordinary_auth_guard_dominates_sink=dominates,
            bypass_path_independently_authorized=authorized,
            cfg_coverage_complete=cfg_complete,
            remaining_human_review_reason=reason,
        ),
        notes=tuple(notes),
    )


def build_open_webui_bypass_development_replay(
    *,
    vulnerable_source: str,
    repair_source: str,
    vulnerable_sha: str = OPEN_WEBUI_VULNERABLE_SHA,
    repair_sha: str = OPEN_WEBUI_REPAIR_SHA,
) -> OpenWebUIBypassDevelopmentReplayReport:
    """Build the dual-revision multi-question development replay report."""

    return OpenWebUIBypassDevelopmentReplayReport(
        vulnerable=analyze_handler_source_for_bypass_replay(
            vulnerable_source,
            revision_sha=vulnerable_sha,
        ),
        repair=analyze_handler_source_for_bypass_replay(
            repair_source,
            revision_sha=repair_sha,
        ),
    )
