# Infrastructure Policy Contract

The infrastructure exposure checker accepts an optional policy file.

## Schema

```text
schemas/infrastructure.policy.schema.json
```

## Policy shape

```json
{
  "blocked_public_sensitivities": ["internal", "confidential", "restricted"]
}
```

## Default

When no policy file is supplied, OVK uses the default policy:

```json
{
  "blocked_public_sensitivities": ["confidential", "restricted"]
}
```

## Runner support

The infrastructure runner accepts:

```text
--policy <path-to-policy-json>
```

## Safety rule

Policy parsing is strict. Unknown sensitivity levels are rejected rather than ignored. This prevents misconfigured policy files from silently weakening the check.
