from ovk.adapters.infra.regression import render_infra_regression_suite, render_infra_regression_test


def test_render_infra_regression_test_contains_resource_id() -> None:
    rendered = render_infra_regression_test(
        {
            "resource_id": "bucket-customer-exports",
            "sensitivity": "confidential",
        }
    )
    assert "bucket-customer-exports" in rendered
    assert "infrastructure regression" in rendered


def test_render_infra_regression_suite_handles_empty_list() -> None:
    rendered = render_infra_regression_suite([])
    assert "No infrastructure exposure counterexamples" in rendered


def test_render_infra_regression_suite_names_tests_uniquely() -> None:
    rendered = render_infra_regression_suite(
        [
            {"resource_id": "bucket-one", "sensitivity": "confidential"},
            {"resource_id": "snapshot-two", "sensitivity": "restricted"},
        ]
    )
    assert "test_sensitive_resource_is_not_publicly_exposed_0" in rendered
    assert "test_sensitive_resource_is_not_publicly_exposed_1" in rendered
