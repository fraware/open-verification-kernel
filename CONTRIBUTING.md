# Contributing

OVK is designed as an open interoperability layer. Contributions should make existing formal methods tools easier to use inside AI-agent engineering workflows.

## Contribution priorities

The highest-priority contributions are:

1. schemas and validation logic;
2. adapter manifests and adapter implementations;
3. property templates with clear engineering value;
4. examples that demonstrate end-to-end PR evidence;
5. tests that prevent evidence dishonesty;
6. benchmark fixtures for agent-authored PR verification.

## Design rules

- Do not add a backend without a capability manifest.
- Do not return a bare boolean from an adapter.
- Do not collapse `unknown`, `error`, or `skipped` into `pass`.
- Do not claim generic verification without assumptions and limits.
- Prefer narrow, useful property templates over broad unverifiable claims.
- Keep the kernel backend-neutral and guarantee-aware.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check ovk tests
```

## Adding an adapter

An adapter must include:

- `capability.json`
- implementation code;
- tests;
- at least one fixture;
- documentation of assumptions and limits;
- normalized result mapping.

## Adding a template

A template must include:

- a verification intent JSON file;
- threat or engineering scenario;
- expected backend class;
- failure modes;
- anti-vacuity considerations;
- example evidence fixture if possible.
