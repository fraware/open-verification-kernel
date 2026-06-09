# Sprint 3 Smoke Update

Added a local authorization smoke script:

```bash
python scripts/smoke_authorization_path.py
```

The script runs the `ovk auth-obligation` command in advisory mode and checks that evidence, Markdown, and attestation outputs are produced for the validation path.

The script is intended for local validation until workflow updates are permitted.
