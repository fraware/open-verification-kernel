# Authorization Input Contract

This document defines the route abstraction consumed by the Sprint 3 authorization path.

## Schema

The formal JSON schema is:

```text
schemas/authorization.input.schema.json
```

## Required top-level field

```json
{
  "routes": []
}
```

`routes` must be a non-empty list.

## Route object

Each route must contain:

```json
{
  "path": "/admin/export",
  "admin_only_before": true,
  "admin_only_after": true,
  "reachable_after": []
}
```

Required fields:

- `path`: non-empty string.
- `admin_only_before`: boolean.
- `admin_only_after`: boolean.
- `reachable_after`: list of witness objects.

## Reachability witness

Each witness must contain a non-empty `role`.

```json
{
  "role": "user",
  "via": ["route_group_added", "middleware_not_applied"]
}
```

`via` is optional, but when supplied it must be a list of strings.

## Safety behavior

Malformed or incomplete route abstractions must not produce `allow`. The validated authorization path returns `unknown` and recommends `require_human_review` when the input fails validation.

## Valid example

```json
{
  "routes": [
    {
      "path": "/admin/export",
      "admin_only_before": true,
      "admin_only_after": true,
      "reachable_after": [
        {
          "role": "admin",
          "via": ["admin_middleware_applied"]
        }
      ]
    }
  ]
}
```

## Invalid examples

Missing routes:

```json
{
  "task": "missing route abstraction"
}
```

Invalid witness:

```json
{
  "routes": [
    {
      "path": "/admin/export",
      "admin_only_before": true,
      "admin_only_after": true,
      "reachable_after": [
        {
          "role": "",
          "via": "middleware_not_applied"
        }
      ]
    }
  ]
}
```
