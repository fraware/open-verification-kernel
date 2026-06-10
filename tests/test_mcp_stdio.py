import json
from pathlib import Path

from ovk.mcp_stdio import handle_request


def test_mcp_tools_list() -> None:
    response = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert response["id"] == 1
    tool_names = {tool["name"] for tool in response["result"]["tools"]}
    assert "ovk.list_capabilities" in tool_names
    assert "ovk.run_verification" in tool_names


def test_mcp_plan_from_diff_tool() -> None:
    diff_text = Path("examples/ci_secrets/workflow_secrets_on_pr.diff").read_text(encoding="utf-8")
    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "ovk.plan_from_diff",
                "arguments": {"diff_text": diff_text},
            },
        }
    )
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["source"] == "unified_diff"
    assert payload["workflow_inputs"]


def test_mcp_run_verification_tool() -> None:
    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "ovk.list_capabilities",
                "arguments": {},
            },
        }
    )
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["release_candidate"] == "1.2.0"
    assert len(payload["supported_evidence_lanes"]) == 5
