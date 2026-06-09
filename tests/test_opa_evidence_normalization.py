from ovk.adapters.opa.evidence import opa_raw_to_evidence


def test_opa_fail_maps_to_blocking_evidence() -> None:
    evidence = opa_raw_to_evidence(
        {"status": "fail", "violations": ["required verification gate removed: ovk-verify"]},
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision["merge_recommendation"] == "block"
    assert evidence.counterexamples[0]["failure_mode"] == "opa_policy_violation"


def test_opa_unknown_maps_to_human_review() -> None:
    evidence = opa_raw_to_evidence(
        {"status": "unknown", "reason": "opa binary not found", "violations": []},
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.counterexamples[0]["failure_mode"] == "opa_unavailable_or_error"


def test_opa_error_maps_to_human_review() -> None:
    evidence = opa_raw_to_evidence(
        {"status": "error", "reason": "invalid output", "violations": []},
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "error"
    assert evidence.decision["merge_recommendation"] == "require_human_review"


def test_opa_pass_maps_to_allow() -> None:
    evidence = opa_raw_to_evidence(
        {"status": "pass", "violations": []},
        repo="example/repo",
        head_sha="abc",
    )
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision["merge_recommendation"] == "allow"
    assert evidence.counterexamples == []
