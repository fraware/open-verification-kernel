# Evidence Quality Report

OVK can now emit a structured evidence quality report for an evidence bundle.

## Purpose

The report records whether an evidence bundle satisfies OVK evidence invariants. It is designed as a release artifact and a future CI gate.

## Schema

```text
ovk.evidence_quality.v1
```

## Contents

- bundle identifier;
- pass or fail result;
- invariant issues, each with path, message, and severity.

## Script

```text
scripts/write_evidence_quality_report.py
```

The script reads an evidence bundle, writes a quality report, and exits non-zero when invariant issues exist.

## Tests

```text
tests/test_evidence_quality.py
tests/test_write_evidence_quality_report.py
```
