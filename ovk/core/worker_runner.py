"""Run backend evaluators behind an externally enforced worker boundary."""

from __future__ import annotations

import json
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ovk.core.execution_budget import BackendWorker, WorkerResult
from ovk.core.execution_models import RawBackendExecution, compute_raw_execution_digests


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class EvaluatorWorkerOutcome:
    """Parsed evaluator output plus worker enforcement metadata."""

    termination: str
    exit_code: int
    raw_result: dict[str, Any]
    native_execution: bool
    timed_out: bool
    worker_rejected: bool
    stderr: str | None
    tool_digest: str | None = None
    worker_image_digest: str | None = None
    isolation_profile: str | None = None
    enforced_controls: tuple[str, ...] = ()
    termination_category: str | None = None
    envelope_produced: bool = False


def run_evaluator_in_worker(
    worker: BackendWorker,
    *,
    evaluator_id: str,
    payload: dict[str, Any],
    timeout_seconds: float,
    cwd: Path | None = None,
) -> EvaluatorWorkerOutcome:
    """Serialize payload, execute evaluator in a subprocess, and parse JSON output."""
    if timeout_seconds <= 0:
        return EvaluatorWorkerOutcome(
            termination="timeout",
            exit_code=1,
            raw_result={"status": "unknown", "reason": "budget timeout"},
            native_execution=False,
            timed_out=False,
            worker_rejected=True,
            stderr=f"non-positive wall-time budget rejected: {timeout_seconds}",
        )

    work_cwd = (cwd or Path.cwd()).resolve()
    with tempfile.TemporaryDirectory(prefix="ovk-worker-", dir=str(work_cwd)) as tmp:
        payload_path = Path(tmp) / "payload.json"
        payload_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        command = (
            sys.executable,
            "-m",
            "ovk.workers.deterministic_entry",
            "--evaluator-id",
            evaluator_id,
            "--payload-file",
            str(payload_path),
        )
        result = worker.run(
            command,
            cwd=work_cwd,
            timeout_seconds=float(timeout_seconds),
            max_stdout_bytes=2_000_000,
            max_stderr_bytes=500_000,
        )
        return _parse_worker_result(result, evaluator_id=evaluator_id)


def _parse_worker_result(result: WorkerResult, *, evaluator_id: str) -> EvaluatorWorkerOutcome:
    extras = {
        "tool_digest": result.tool_digest,
        "worker_image_digest": result.worker_image_digest,
        "isolation_profile": result.isolation_profile,
        "enforced_controls": result.enforced_controls,
        "termination_category": result.termination_category,
    }
    if result.timed_out:
        return EvaluatorWorkerOutcome(
            termination="timeout",
            exit_code=1,
            raw_result={"status": "unknown", "reason": "worker execution timed out"},
            native_execution=False,
            timed_out=True,
            worker_rejected=False,
            stderr=result.stderr or None,
            **extras,
        )
    if result.exit_code is None:
        termination = "tool_unavailable" if result.termination_category == "isolation_unenforceable" else "tool_error"
        return EvaluatorWorkerOutcome(
            termination=termination,
            exit_code=1,
            raw_result={
                "status": "error",
                "reason": result.stderr.strip() or "worker rejected execution",
                "isolation_profile": result.isolation_profile,
                "enforced_controls": list(result.enforced_controls),
                "termination_category": result.termination_category,
            },
            native_execution=False,
            timed_out=False,
            worker_rejected=True,
            stderr=result.stderr or None,
            **extras,
        )
    if not result.stdout.strip():
        return EvaluatorWorkerOutcome(
            termination="invalid_output",
            exit_code=1,
            raw_result={
                "status": "error",
                "reason": result.stderr.strip() or f"{evaluator_id} returned empty output",
            },
            native_execution=False,
            timed_out=False,
            worker_rejected=False,
            stderr=result.stderr or None,
            **extras,
        )
    try:
        envelope = json.loads(result.stdout)
    except json.JSONDecodeError:
        return EvaluatorWorkerOutcome(
            termination="invalid_output",
            exit_code=1,
            raw_result={
                "status": "error",
                "reason": "worker returned invalid JSON",
            },
            native_execution=False,
            timed_out=False,
            worker_rejected=False,
            stderr=result.stderr or None,
            **extras,
        )
    if not isinstance(envelope, dict):
        return EvaluatorWorkerOutcome(
            termination="invalid_output",
            exit_code=1,
            raw_result={"status": "error", "reason": "worker returned non-object JSON"},
            native_execution=False,
            timed_out=False,
            worker_rejected=False,
            stderr=result.stderr or None,
            **extras,
        )
    return EvaluatorWorkerOutcome(
        termination=str(envelope.get("termination", "completed")),
        exit_code=int(envelope.get("exit_code", result.exit_code or 1)),
        raw_result=dict(envelope.get("raw_result") or {}),
        native_execution=bool(envelope.get("native_execution", False)),
        timed_out=False,
        worker_rejected=False,
        stderr=result.stderr or None,
        envelope_produced=True,
        **extras,
    )


def raw_execution_from_worker_outcome(
    *,
    backend: str,
    backend_obligation_id: str,
    adapter_version: str,
    outcome: EvaluatorWorkerOutcome,
    started_at: str,
    duration_ms: float,
) -> RawBackendExecution:
    """Project a worker outcome into ``RawBackendExecution``."""
    raw = RawBackendExecution(
        backend=backend,
        backend_obligation_id=backend_obligation_id,
        termination=outcome.termination,  # type: ignore[arg-type]
        native_execution=outcome.native_execution,
        exit_code=outcome.exit_code,
        stderr=outcome.stderr,
        raw_result=outcome.raw_result,
        started_at=started_at,
        finished_at=_utc_now_iso(),
        duration_ms=duration_ms,
        tool_version=adapter_version,
        tool_digest=outcome.tool_digest,
        worker_image_digest=outcome.worker_image_digest,
        envelope_produced=outcome.envelope_produced,
    )
    return raw.model_copy(update=compute_raw_execution_digests(raw))


def require_worker(
    worker: BackendWorker | None,
    *,
    backend: str,
    backend_obligation_id: str,
    adapter_version: str,
) -> BackendWorker:
    """Fail closed when an authoritative adapter is invoked without a worker."""
    if worker is not None:
        return worker
    started_at = _utc_now_iso()
    raise WorkerRequiredError(
        raw_execution_from_worker_outcome(
            backend=backend,
            backend_obligation_id=backend_obligation_id,
            adapter_version=adapter_version,
            outcome=EvaluatorWorkerOutcome(
                termination="tool_error",
                exit_code=1,
                raw_result={
                    "status": "error",
                    "reason": "authoritative adapter requires BackendWorker; in-process execution forbidden",
                },
                native_execution=False,
                timed_out=False,
                worker_rejected=True,
                stderr="missing worker",
            ),
            started_at=started_at,
            duration_ms=0.0,
        )
    )


class WorkerRequiredError(Exception):
    """Raised when an adapter is invoked without a required worker."""

    def __init__(self, raw: RawBackendExecution) -> None:
        super().__init__("authoritative adapter requires BackendWorker")
        self.raw = raw


def run_with_required_worker(
    worker: BackendWorker | None,
    *,
    backend: str,
    backend_obligation_id: str,
    adapter_version: str,
    evaluator_id: str,
    payload: dict[str, Any],
    timeout_seconds: float,
    cwd: Path | None = None,
) -> RawBackendExecution:
    """Execute an evaluator in a worker or return a fail-closed raw execution."""
    started = time.perf_counter()
    started_at = _utc_now_iso()
    if worker is None:
        try:
            require_worker(
                None,
                backend=backend,
                backend_obligation_id=backend_obligation_id,
                adapter_version=adapter_version,
            )
        except WorkerRequiredError as exc:
            return exc.raw
    assert worker is not None
    outcome = run_evaluator_in_worker(
        worker,
        evaluator_id=evaluator_id,
        payload=payload,
        timeout_seconds=timeout_seconds,
        cwd=cwd,
    )
    return raw_execution_from_worker_outcome(
        backend=backend,
        backend_obligation_id=backend_obligation_id,
        adapter_version=adapter_version,
        outcome=outcome,
        started_at=started_at,
        duration_ms=(time.perf_counter() - started) * 1000.0,
    )
