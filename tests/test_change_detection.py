from ovk.core.change_detection import detect_change_surfaces, infer_candidate_intents


def test_ci_change_selects_self_protection_intent() -> None:
    intents = infer_candidate_intents([".github/workflows/verify.yml"])
    assert "agent-cannot-disable-own-ci-gate" in intents


def test_authorization_change_selects_auth_intent() -> None:
    intents = infer_candidate_intents(["src/middleware/auth.py", "src/routes/admin.py"])
    assert "no-admin-route-bypass" in intents


def test_infrastructure_change_selects_infra_intent() -> None:
    intents = infer_candidate_intents(["main.tf"])
    assert "no-public-sensitive-resource" in intents


def test_detect_change_surfaces_groups_files() -> None:
    surfaces = detect_change_surfaces(
        [
            ".github/workflows/verify.yml",
            "src/middleware/auth.py",
            "main.tf",
        ]
    )
    domains = {surface.domain for surface in surfaces}
    assert {"ci_cd", "authorization", "infrastructure"}.issubset(domains)
