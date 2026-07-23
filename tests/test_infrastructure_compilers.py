"""Infrastructure compiler and worker tests."""

from __future__ import annotations

import os
from pathlib import Path

from ovk.compilers.infrastructure import (
    compile_kubernetes_objects,
    compile_terraform_plan,
    sensitive_public_violations,
)
from ovk.core.execution_budget import LocalSubprocessWorker


def test_terraform_plan_json_public_sensitive() -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_s3_bucket.exports",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "tags": {"sensitivity": "confidential"},
                        "acl": "public-read",
                    }
                },
            }
        ],
    }
    ir = compile_terraform_plan(plan)
    assert ir.source_kind == "terraform_plan"
    assert ir.resources
    assert ir.resources[0].sensitivity == "confidential"
    assert ir.resources[0].public_exposure is True
    assert ir.public_paths
    assert ir.eligibility in {"strict", "review"}
    assert sensitive_public_violations(ir)


def test_terraform_missing_after_is_review() -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [{"address": "aws_s3_bucket.x", "type": "aws_s3_bucket", "change": {}}],
    }
    ir = compile_terraform_plan(plan)
    assert ir.eligibility == "review"
    assert any("missing_after" in item for item in ir.unsupported_constructs)


def test_public_without_concrete_path_is_review() -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_s3_bucket.private",
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "tags": {"sensitivity": "confidential"},
                        "public_exposure": True,
                    }
                },
            }
        ],
    }
    ir = compile_terraform_plan(plan)
    # declared public without concrete exposure_paths => review
    assert ir.eligibility == "review"
    assert any("concrete path" in reason or "without concrete" in reason for reason in ir.eligibility_reasons)


def test_kubernetes_service_and_ingress() -> None:
    objects = [
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "api",
                "namespace": "prod",
                "annotations": {"ovk.io/sensitivity": "confidential"},
            },
            "spec": {"type": "LoadBalancer"},
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"name": "api-ing", "namespace": "prod"},
            "spec": {
                "rules": [
                    {
                        "http": {
                            "paths": [
                                {
                                    "backend": {"service": {"name": "api"}},
                                }
                            ]
                        }
                    }
                ]
            },
        },
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "runner", "namespace": "prod"},
            "secrets": [{"name": "runner-token"}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "reader", "namespace": "prod"},
            "rules": [{"resources": ["secrets"], "verbs": ["get"]}],
        },
    ]
    ir = compile_kubernetes_objects(objects)
    kinds = {item.resource_type for item in ir.resources}
    assert "Service" in kinds
    assert "Ingress" in kinds
    assert "ServiceAccount" in kinds
    assert "Role" in kinds
    assert any(item.public_exposure for item in ir.resources)


def test_local_subprocess_worker_timeout_and_bounds(tmp_path: Path) -> None:
    worker = LocalSubprocessWorker(bound_roots=(tmp_path,))
    result = worker.run(
        ["python", "-c", "import time; time.sleep(2)"],
        cwd=tmp_path,
        timeout_seconds=0.2,
        max_stdout_bytes=100,
    )
    assert result.timed_out is True


def test_local_subprocess_worker_blocks_outside_cwd(tmp_path: Path) -> None:
    worker = LocalSubprocessWorker(bound_roots=(tmp_path,))
    outside = tmp_path.parent
    result = worker.run(["python", "-c", "print(1)"], cwd=outside, timeout_seconds=5)
    assert result.exit_code is None
    assert "outside bound roots" in result.stderr


def test_local_subprocess_worker_strips_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "super-secret")
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    worker = LocalSubprocessWorker(bound_roots=(tmp_path,))
    result = worker.run(
        ["python", "-c", "import os; print(os.environ.get('GITHUB_TOKEN', ''))"],
        cwd=tmp_path,
        timeout_seconds=5,
    )
    assert result.timed_out is False
    assert result.exit_code == 0
    assert "super-secret" not in result.stdout
