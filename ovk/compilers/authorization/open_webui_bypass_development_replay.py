"""Open WebUI bypass development-replay report (#125 / residual live pins).

This is an explicitly labeled **development replay**. It does not mutate the
frozen round-2 registry and must not be counted as held-out success.

Default CI path uses synthetic fixtures. An explicit gated live-replay path
(``OVK_OPEN_WEBUI_LIVE_REPLAY=1``) fetches the pinned Open WebUI revisions when
network/clone is available and answers the same seven questions from real
source. Live results remain ``development_replay`` — never held-out success.

Pinned revisions (round 2):

- vulnerable: ``30068afd780e034f0c116419103672d7315a7fe3``
- repair: ``c0385f60ba049da48d2d5452068586d375303c37``

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
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Literal, Mapping

from ovk.compilers.authorization.bypass_authority import (
    analyze_bypass_authority,
    analyze_bypass_authority_unit,
)
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
OPEN_WEBUI_REPO = "open-webui/open-webui"
OPEN_WEBUI_LIVE_REPLAY_ENV = "OVK_OPEN_WEBUI_LIVE_REPLAY"

# Sparse pin paths that carry the bypass authority change under the repair commit.
OPEN_WEBUI_PIN_RELATIVE_PATHS: tuple[str, ...] = (
    "backend/open_webui/utils/chat.py",
    "backend/open_webui/routers/openai.py",
    "backend/open_webui/routers/ollama.py",
)

ReplayLabel = Literal["development_replay"]
ReplaySourceMode = Literal["synthetic_fixture", "live_pin"]


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
    source_mode: ReplaySourceMode = "synthetic_fixture"


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
    source_mode: ReplaySourceMode = "synthetic_fixture"

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "label": self.label,
            "held_out_success": self.held_out_success,
            "frozen_registry_mutated": self.frozen_registry_mutated,
            "source_mode": self.source_mode,
            "vulnerable": {
                "revision_sha": self.vulnerable.revision_sha,
                "label": self.vulnerable.label,
                "source_mode": self.vulnerable.source_mode,
                "answers": asdict(self.vulnerable.answers),
                "notes": list(self.vulnerable.notes),
            },
            "repair": {
                "revision_sha": self.repair.revision_sha,
                "label": self.repair.label,
                "source_mode": self.repair.source_mode,
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
    source_mode: ReplaySourceMode = "synthetic_fixture",
    unit_files: Mapping[str, str] | None = None,
) -> OpenWebUIBypassReplayRevisionReport:
    """Analyze one source unit for the multi-question replay report.

    Generic needles keep this helper free of Open WebUI-specific extractor
    identifiers while still supporting pinned Open WebUI development fixtures.
    When ``unit_files`` is provided, closed-world bypass authority uses the
    multi-file compilation unit.
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
        origin_sources = unit_files or {path: source}
        for origin_path, origin_source in sorted(origin_sources.items()):
            origin_tree = ast.parse(origin_source)
            for fn in _module_functions(origin_tree):
                origins.extend(
                    extract_value_origins_from_source(
                        origin_source,
                        path=origin_path,
                        function_name=fn.name,
                    )
                )
        if unit_files is not None:
            bypass_findings = analyze_bypass_authority_unit(
                unit_files,
                entry_path=path,
                function_name=handler.name,
                bypass_fields=frozenset({bypass_field}),
            )
        else:
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
            source_mode=source_mode,
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
        # Live vulnerable pins expose bypass_filter as an ordinary HTTP param on
        # the route handler (before the request.state repair). Treat that as
        # client-controlled even when request.state writers are absent.
        http_param_bypass = any(
            item.origin_kind == "externally_bound_http_value"
            and (
                item.source_expression == bypass_field
                or item.value_id == f"value:param:{bypass_field}"
            )
            for item in origins
            if item.origin.path == path
        )
        if matching:
            bypass_status = matching[0].status
            authorized = matching[0].status == "authorized"
            if matching[0].status == "violated" or (
                matching[0].status == "unknown" and http_param_bypass
            ):
                if http_param_bypass and matching[0].status != "violated":
                    bypass_status = "violated"
                    authorized = False
                    notes.append("client_controlled_http_param_bypass")
                elif matching[0].status == "violated":
                    notes.append("client_controlled_bypass")
                elif matching[0].status == "unknown":
                    notes.append(matching[0].reason)
            elif matching[0].status == "unknown":
                notes.append(matching[0].reason)
        elif http_param_bypass:
            bypass_status = "violated"
            authorized = False
            notes.append("client_controlled_http_param_bypass")
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
        source_mode=source_mode,
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
            source_mode="synthetic_fixture",
        ),
        repair=analyze_handler_source_for_bypass_replay(
            repair_source,
            revision_sha=repair_sha,
            source_mode="synthetic_fixture",
        ),
        source_mode="synthetic_fixture",
    )


def live_open_webui_replay_enabled() -> bool:
    """True when the explicit live-pin gate is set."""

    return os.environ.get(OPEN_WEBUI_LIVE_REPLAY_ENV, "").strip() in {
        "1",
        "true",
        "TRUE",
        "yes",
        "YES",
    }


def fetch_open_webui_pin_file(
    relative_path: str,
    *,
    revision_sha: str,
    repo: str = OPEN_WEBUI_REPO,
    timeout_s: float = 30.0,
) -> str:
    """Fetch one repository-relative file at a pinned SHA via the GitHub API."""

    import base64

    url = (
        f"https://api.github.com/repos/{repo}/contents/"
        f"{relative_path}?ref={revision_sha}"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ovk-open-webui-development-replay",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            payload = json_loads_safe(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"failed to fetch {relative_path}@{revision_sha}: "
            f"HTTP {exc.code}: {body[:200]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"network unavailable for {relative_path}@{revision_sha}: {exc}"
        ) from exc

    content = payload.get("content")
    encoding = payload.get("encoding")
    if not isinstance(content, str):
        raise RuntimeError(
            f"unexpected GitHub contents payload for {relative_path}@{revision_sha}"
        )
    if encoding == "base64":
        return base64.b64decode(content).decode("utf-8")
    return content


def json_loads_safe(text: str) -> dict[str, Any]:
    import json

    data = json.loads(text)
    if not isinstance(data, dict):
        raise RuntimeError("expected object JSON from GitHub contents API")
    return data


def fetch_open_webui_pin_unit(
    *,
    revision_sha: str,
    relative_paths: tuple[str, ...] = OPEN_WEBUI_PIN_RELATIVE_PATHS,
    repo: str = OPEN_WEBUI_REPO,
) -> dict[str, str]:
    """Sparse-fetch the pin-relevant files for one Open WebUI revision."""

    files: dict[str, str] = {}
    for relative_path in relative_paths:
        files[relative_path] = fetch_open_webui_pin_file(
            relative_path,
            revision_sha=revision_sha,
            repo=repo,
        )
    return files


def _pick_live_entry_path(files: Mapping[str, str]) -> str:
    for candidate in (
        "backend/open_webui/routers/openai.py",
        "backend/open_webui/routers/ollama.py",
    ):
        if candidate in files:
            return candidate
    return sorted(files)[0]


def analyze_open_webui_live_pin_revision(
    *,
    revision_sha: str,
    files: Mapping[str, str] | None = None,
) -> OpenWebUIBypassReplayRevisionReport:
    """Answer the seven development-replay questions from a live pin unit."""

    unit = files or fetch_open_webui_pin_unit(revision_sha=revision_sha)
    entry = _pick_live_entry_path(unit)
    return analyze_handler_source_for_bypass_replay(
        unit[entry],
        revision_sha=revision_sha,
        path=entry,
        function_name="generate_chat_completion",
        # Distinct needles: access check vs later request construction. Live
        # CFG binding may remain partial; closed-world bypass answers carry
        # the material CVE signal.
        sink_needle="metadata",
        guard_needle="check_model_access",
        bypass_field="bypass_filter",
        source_mode="live_pin",
        unit_files=unit,
    )


def build_open_webui_bypass_live_development_replay(
    *,
    vulnerable_sha: str = OPEN_WEBUI_VULNERABLE_SHA,
    repair_sha: str = OPEN_WEBUI_REPAIR_SHA,
    require_gate: bool = True,
) -> OpenWebUIBypassDevelopmentReplayReport:
    """Fetch pinned Open WebUI revisions and build a live development replay.

    Requires ``OVK_OPEN_WEBUI_LIVE_REPLAY=1`` when ``require_gate`` is true so
    CI keeps using synthetic fixtures unless explicitly opted in. Live results
    are still labeled ``development_replay`` and never held-out success.
    """

    if require_gate and not live_open_webui_replay_enabled():
        raise RuntimeError(
            f"live Open WebUI pin replay requires {OPEN_WEBUI_LIVE_REPLAY_ENV}=1; "
            "synthetic fixtures remain the default CI path"
        )

    vulnerable_files = fetch_open_webui_pin_unit(revision_sha=vulnerable_sha)
    repair_files = fetch_open_webui_pin_unit(revision_sha=repair_sha)
    return OpenWebUIBypassDevelopmentReplayReport(
        vulnerable=analyze_open_webui_live_pin_revision(
            revision_sha=vulnerable_sha,
            files=vulnerable_files,
        ),
        repair=analyze_open_webui_live_pin_revision(
            revision_sha=repair_sha,
            files=repair_files,
        ),
        source_mode="live_pin",
    )
