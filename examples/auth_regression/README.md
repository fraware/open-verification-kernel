# Example: Authorization Regression

## Scenario

An AI coding agent receives the issue:

```text
Add an export endpoint for admin analytics.
```

The agent modifies route and middleware files. The new `/admin/export` endpoint is accidentally reachable by non-admin users.

## Expected OVK behavior

OVK should:

1. detect changes to authorization-sensitive files;
2. select the `no-admin-route-bypass` intent;
3. build a small reachability abstraction;
4. route to the Z3 adapter or policy adapter;
5. return a counterexample showing a non-admin user reaching an admin-only route;
6. generate a regression test;
7. block the PR in enforce mode.

## Counterexample shape

```json
{
  "user_role": "user",
  "route": "/admin/export",
  "path": [
    "route_group_added",
    "middleware_not_applied",
    "handler_reachable"
  ]
}
```

## Generated regression test shape

```python
def test_non_admin_cannot_export_admin_data(client, make_user, auth):
    user = make_user(role="user")
    response = client.get("/admin/export", headers=auth(user))
    assert response.status_code == 403
```
