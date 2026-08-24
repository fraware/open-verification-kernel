"""GitHub Actions effective-principal and environment-trust regressions."""

from ovk.compilers.github_actions.permissions import effective_permissions_for_job, has_write_token
from ovk.compilers.github_actions.trust_flow import compile_workflow_trust


def _write_findings(workflow: dict):
    return [
        finding
        for finding in compile_workflow_trust(workflow).findings
        if finding.kind == "untrusted_code_with_write_token"
    ]


def test_job_permissions_replace_workflow_permissions_for_effective_authority() -> None:
    workflow = {
        "permissions": {"contents": "write", "issues": "write"},
        "jobs": {
            "safe": {
                "permissions": {"contents": "read"},
                "runs-on": "ubuntu-latest",
                "steps": [{"run": "echo safe"}],
            }
        },
    }
    grants, source = effective_permissions_for_job(workflow, "safe")
    assert source == "job"
    assert [(grant.scope, grant.level) for grant in grants] == [("contents", "read")]
    assert has_write_token(grants) is False


def test_write_permission_in_one_job_does_not_contaminate_other_job() -> None:
    workflow = {
        "on": {"pull_request_target": {}},
        "permissions": {"contents": "read"},
        "jobs": {
            "safe": {
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "safe", "run": "echo safe"}],
            },
            "privileged": {
                "permissions": {"issues": "write"},
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "privileged", "run": "echo privileged"}],
            },
        },
    }
    findings = _write_findings(workflow)
    assert len(findings) == 1
    assert findings[0].node_ids == ["job:privileged:step:privileged"]
    assert findings[0].evidence["permission_source"] == "job"


def test_job_read_override_contracts_workflow_write_while_other_job_inherits() -> None:
    workflow = {
        "on": {"pull_request_target": {}},
        "permissions": {"contents": "write"},
        "jobs": {
            "safe": {
                "permissions": {"contents": "read"},
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "safe", "run": "echo safe"}],
            },
            "inherits": {
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "inherits", "run": "echo inherited"}],
            },
        },
    }
    findings = _write_findings(workflow)
    assert len(findings) == 1
    assert findings[0].node_ids == ["job:inherits:step:inherits"]
    assert findings[0].evidence["permission_source"] == "workflow"


def test_pull_request_target_without_explicit_permissions_is_privileged_risk() -> None:
    workflow = {
        "on": {"pull_request_target": {}},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "run", "run": "echo ${{ github.event.pull_request.title }}"}],
            }
        },
    }
    findings = _write_findings(workflow)
    assert len(findings) == 1
    assert findings[0].evidence["permission_source"] == "pull_request_target_default"


def test_explicit_empty_permissions_remove_pull_request_target_write_risk() -> None:
    workflow = {
        "on": {"pull_request_target": {}},
        "permissions": {},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "run", "run": "echo safe"}],
            }
        },
    }
    assert _write_findings(workflow) == []


def test_plain_pull_request_default_permissions_are_reported_unknown_not_write() -> None:
    workflow = {
        "on": {"pull_request": {}},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "run", "run": "echo safe"}],
            }
        },
    }
    ir = compile_workflow_trust(workflow)
    assert [finding for finding in ir.findings if finding.kind == "untrusted_code_with_write_token"] == []
    assert "job:build:default_token_permissions_repository_dependent" in ir.warnings


def test_environment_syntax_cannot_self_assert_protection() -> None:
    workflow = {
        "on": {"pull_request_target": {}},
        "permissions": {},
        "_ovk_protected_environments": ["production"],
        "jobs": {
            "deploy": {
                "environment": "production",
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "deploy", "run": "echo deploy"}],
            }
        },
    }
    without_acquired_metadata = compile_workflow_trust(workflow)
    assert [
        finding for finding in without_acquired_metadata.findings
        if finding.kind == "untrusted_code_with_protected_env"
    ] == []

    with_acquired_metadata = compile_workflow_trust(
        workflow,
        protected_environments={"production"},
    )
    findings = [
        finding for finding in with_acquired_metadata.findings
        if finding.kind == "untrusted_code_with_protected_env"
    ]
    assert len(findings) == 1
    assert findings[0].evidence["environment"] == "production"
