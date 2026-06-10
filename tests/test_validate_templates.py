from scripts.validate_templates import validate_templates
from ovk.paths import resource_path


def test_all_templates_validate_against_schema() -> None:
    failures = validate_templates()
    assert failures == []


def test_template_library_has_hardening_target_count() -> None:
    templates = list(resource_path("templates").rglob("*.intent.json"))
    assert len(templates) >= 100
