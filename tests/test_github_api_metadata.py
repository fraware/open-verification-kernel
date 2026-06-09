from ovk.core.github_api_metadata import (
    GitHubApiConfig,
    branch_protection_url,
    config_from_environment,
    required_checks_from_branch_protection,
)


def test_branch_protection_url_encodes_branch() -> None:
    config = GitHubApiConfig(repository="owner/repo", branch="feature/test branch")
    assert branch_protection_url(config) == (
        "https://api.github.com/repos/owner/repo/branches/feature%2Ftest%20branch/protection"
    )


def test_required_checks_from_branch_protection_contexts() -> None:
    branch_protection = {
        "required_status_checks": {
            "contexts": ["unit-tests", "ovk-verify"],
        }
    }
    assert required_checks_from_branch_protection(branch_protection) == ["unit-tests", "ovk-verify"]


def test_required_checks_from_branch_protection_checks_shape() -> None:
    branch_protection = {
        "required_status_checks": {
            "checks": [
                {"context": "unit-tests"},
                {"context": "ovk-verify"},
            ],
        }
    }
    assert required_checks_from_branch_protection(branch_protection) == ["unit-tests", "ovk-verify"]


def test_config_from_environment_missing_values_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    assert config_from_environment() is None


def test_config_from_environment_uses_explicit_values() -> None:
    config = config_from_environment(repository="owner/repo", branch="main")
    assert config is not None
    assert config.repository == "owner/repo"
    assert config.branch == "main"
