import json
from pathlib import Path

from ovk.mcp_stdio import handle_request


def test_mcp_rank_intents_tool() -> None:
    diff_text = Path("examples/ci_secrets/workflow_secrets_on_pr.diff").read_text(encoding="utf-8")
    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "ovk.rank_intents",
                "arguments": {"diff_text": diff_text},
            },
        }
    )
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["ranked_intents"]


def test_mcp_select_backends_tool() -> None:
    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "ovk.select_backends",
                "arguments": {"intent_id": "no-admin-route-bypass"},
            },
        }
    )
    payload = json.loads(response["result"]["content"][0]["text"])
    assert "selected" in payload
