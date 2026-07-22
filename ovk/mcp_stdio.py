"""Minimal MCP-compatible stdio server for Open Verification Kernel."""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

from ovk import mcp_server
from ovk.core.release_metadata import OVK_VERSION


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "open-verification-kernel"
SERVER_VERSION = OVK_VERSION


TOOL_HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "ovk.extract_intents": lambda args: mcp_server.extract_intents(args.get("changed_files", [])),
    "ovk.plan_from_diff": lambda args: mcp_server.plan_from_diff(
        str(args.get("diff_text", "")),
        trust_context=str(args.get("trust_context", "untrusted_fork_pr")),
    ),
    "ovk.extract_workflow_yaml": lambda args: mcp_server.extract_workflow_yaml(
        str(args.get("yaml_text", "")),
        workflow_id=str(args.get("workflow_id", "workflow")),
    ),
    "ovk.extract_workflows_from_diff": lambda args: mcp_server.extract_workflows_from_diff(
        str(args.get("diff_text", "")),
        trust_context=str(args.get("trust_context", "untrusted_fork_pr")),
    ),
    "ovk.list_capabilities": lambda _args: mcp_server.list_capabilities(),
    "ovk.run_verification": lambda args: {
        "evidence": mcp_server.run_verification(
            str(args.get("lane", "")),
            args.get("input_data", {}),
            repo=args.get("repo", "unknown/repo"),
            head_sha=args.get("head_sha", "unknown"),
            base_sha=args.get("base_sha"),
            input_format=args.get("input_format", "infra"),
            policy_path=args.get("policy_path"),
        )
    },
    "ovk.create_evidence_bundle": lambda args: {
        "bundle": mcp_server.create_evidence_bundle(args.get("evidence_items", []))
    },
    "ovk.get_merge_recommendation": lambda args: mcp_server.get_merge_recommendation(args.get("evidence_bundle", {})),
    "ovk.explain_result": lambda args: mcp_server.explain_result(args.get("evidence_bundle", {})),
    "ovk.rank_intents": lambda args: mcp_server.rank_intents_tool(
        changed_files=args.get("changed_files"),
        diff_text=args.get("diff_text"),
    ),
    "ovk.compile_obligation": lambda args: mcp_server.compile_obligation(
        changed_files=args.get("changed_files"),
        diff_text=args.get("diff_text"),
        repo=args.get("repo", "unknown/repo"),
        head_sha=args.get("head_sha", "unknown"),
        base_sha=args.get("base_sha"),
    ),
    "ovk.select_backends": lambda args: mcp_server.select_backends(
        str(args.get("intent_id", "")),
        changed_files=args.get("changed_files"),
    ),
    "ovk.generate_regression_artifact": lambda args: mcp_server.generate_regression_artifact(
        args.get("evidence_bundle", {})
    ),
}


def _tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": f"Open Verification Kernel tool {name}",
            "inputSchema": {"type": "object", "additionalProperties": True},
        }
        for name in TOOL_HANDLERS
    ]


def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    """Handle one JSON-RPC request."""
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _tool_definitions()}}

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"unknown tool: {tool_name}"},
            }
        try:
            payload = handler(arguments if isinstance(arguments, dict) else {})
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                    "structuredContent": payload,
                },
            }
        except Exception as error:  # noqa: BLE001 - surface tool failures to MCP client
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": str(error)},
            }

    if method == "notifications/initialized":
        return {}

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"unsupported method: {method}"},
    }


def serve_stdio() -> None:
    """Run the MCP stdio loop."""
    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue
        request = json.loads(stripped)
        response = handle_request(request)
        if response:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


def main() -> None:
    """Entry point for `ovk-mcp`."""
    try:
        from ovk.mcp_sdk_transport import serve_with_sdk

        serve_with_sdk()
    except ImportError:
        serve_stdio()


if __name__ == "__main__":
    main()
