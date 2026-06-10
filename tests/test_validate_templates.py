from scripts.validate_templates import validate_templates


def test_all_templates_validate_against_schema() -> None:
    failures = validate_templates()
    assert failures == []
