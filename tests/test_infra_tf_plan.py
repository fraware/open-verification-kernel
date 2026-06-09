from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.infra.tf_plan import terraform_plan_to_infra_input


def test_terraform_plan_public_confidential_bucket_blocks() -> None:
    plan = {
        "author_type": "ai_agent",
        "agent": "codex",
        "resource_changes": [
            {
                "type": "aws_s3_bucket",
                "name": "customer_exports",
                "change": {
                    "after": {
                        "tags": {"sensitivity": "confidential"},
                        "acl": "public-read",
                    }
                },
            }
        ],
    }
    infra_input = terraform_plan_to_infra_input(plan)
    evidence = evaluate_infra_exposure(infra_input, repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "block"
    assert evidence.counterexamples[0]["resource_type"] == "aws_s3_bucket"


def test_terraform_plan_private_confidential_bucket_allows() -> None:
    plan = {
        "resource_changes": [
            {
                "type": "aws_s3_bucket",
                "name": "customer_exports",
                "change": {
                    "after": {
                        "tags": {"classification": "confidential"},
                        "acl": "private",
                    }
                },
            }
        ],
    }
    infra_input = terraform_plan_to_infra_input(plan)
    evidence = evaluate_infra_exposure(infra_input, repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "allow"
    assert evidence.counterexamples == []


def test_terraform_plan_public_internal_resource_allows() -> None:
    plan = {
        "resource_changes": [
            {
                "type": "aws_lb",
                "name": "public_frontend",
                "change": {
                    "after": {
                        "tags": {"sensitivity": "internal"},
                        "internet_accessible": True,
                    }
                },
            }
        ],
    }
    infra_input = terraform_plan_to_infra_input(plan)
    evidence = evaluate_infra_exposure(infra_input, repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "allow"


def test_empty_terraform_plan_becomes_invalid_infra_input() -> None:
    infra_input = terraform_plan_to_infra_input({"resource_changes": []})
    evidence = evaluate_infra_exposure(infra_input, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
