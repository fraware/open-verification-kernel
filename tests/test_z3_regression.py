from ovk.adapters.z3.regression import (
    render_authorization_regression_suite,
    render_authorization_regression_test,
)


def test_render_authorization_regression_test_contains_route_and_role() -> None:
    rendered = render_authorization_regression_test(
        {
            "route": "/admin/export",
            "user_role": "user",
        }
    )
    assert "/admin/export" in rendered
    assert "user" in rendered
    assert "authorization regression" in rendered


def test_render_authorization_regression_suite_handles_empty_list() -> None:
    rendered = render_authorization_regression_suite([])
    assert "No authorization counterexamples" in rendered


def test_render_authorization_regression_suite_names_tests_uniquely() -> None:
    rendered = render_authorization_regression_suite(
        [
            {"route": "/admin/export", "user_role": "user"},
            {"route": "/admin/delete", "user_role": "guest"},
        ]
    )
    assert "test_non_admin_cannot_reach_admin_route_0" in rendered
    assert "test_non_admin_cannot_reach_admin_route_1" in rendered
