"""Subprocess worker entry points for isolated backend evaluation."""

from __future__ import annotations

import argparse
import json
import sys

from ovk.core.deterministic_evaluators import evaluate_deterministic


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an OVK evaluator in an isolated worker process.")
    parser.add_argument("--evaluator-id", required=True)
    parser.add_argument("--payload-file", required=True)
    args = parser.parse_args(argv)

    payload = json.loads(open(args.payload_file, encoding="utf-8").read())
    result = evaluate_deterministic(args.evaluator_id, payload)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
