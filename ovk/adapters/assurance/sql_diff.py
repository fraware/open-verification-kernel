"""SQL state-difference assurance verifier (VA-10)."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from ovk.adapters.assurance._support import (
    AssuranceBackendMixin,
    accept_outcome,
    indeterminate_run_outcome,
    reject_outcome,
)
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.snapshot import ConfigurationSnapshot, build_configuration_snapshot


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest}"
from ovk.core.execution_models import (
    AssuranceAbstention,
    AssuranceCapabilitySection,
    AssuranceDecisionSemantics,
    AssuranceFailureBehavior,
    AssuranceReplaySupport,
    AssuranceSnapshotSupport,
    AssuranceVerifierIdentity,
    BackendCapabilityManifest,
    BackendGuaranteeDeclaration,
    BackendToolIdentity,
)

GUARANTEE_CLASS = "observational"

_DECISION_SPACE = [
    "accept",
    "reject",
    "indeterminate_execution_error",
    "indeterminate_out_of_scope",
    "indeterminate_insufficient_evidence",
]


def _connect(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA query_only = ON")
    return conn


def _schema_digest(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table','index','view','trigger') ORDER BY type, name"
    ).fetchall()
    return sha256_digest([list(row) for row in rows])


def _table_names(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [str(row[0]) for row in rows]


def _table_digest(conn: sqlite3.Connection, table: str) -> str:
    rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
    return sha256_digest([list(row) for row in rows])


def diff_sqlite(before_path: Path, after_path: Path, tables: list[str] | None = None) -> dict[str, Any]:
    """Compute a deterministic state difference between two SQLite databases."""
    before_conn = _connect(before_path)
    after_conn = _connect(after_path)
    try:
        before_schema = _schema_digest(before_conn)
        after_schema = _schema_digest(after_conn)
        before_tables = _table_names(before_conn)
        after_tables = _table_names(after_conn)
        selected = tables or sorted(set(before_tables) | set(after_tables))
        table_diffs: list[dict[str, Any]] = []
        for table in selected:
            in_before = table in before_tables
            in_after = table in after_tables
            if not in_before or not in_after:
                table_diffs.append(
                    {
                        "table": table,
                        "changed": True,
                        "before_present": in_before,
                        "after_present": in_after,
                    }
                )
                continue
            b_digest = _table_digest(before_conn, table)
            a_digest = _table_digest(after_conn, table)
            table_diffs.append(
                {
                    "table": table,
                    "changed": b_digest != a_digest,
                    "before_digest": b_digest,
                    "after_digest": a_digest,
                }
            )
        return {
            "before_schema_digest": before_schema,
            "after_schema_digest": after_schema,
            "schema_changed": before_schema != after_schema,
            "tables": table_diffs,
            "changed_tables": [item["table"] for item in table_diffs if item.get("changed")],
        }
    finally:
        before_conn.close()
        after_conn.close()


class SqlStateDiffAdapter(AssuranceBackendMixin):
    """Real SQL state difference over SQLite offline fixtures."""

    backend_id = "sql-state-diff"
    adapter_id = "ovk-adapter-sql-state-diff"
    adapter_version = "0.1.0"
    _guarantee_type = "state_diff"

    def __init__(self, *, timeout_ms: int = 15_000) -> None:
        self.timeout_ms = timeout_ms

    def supported_mutation_dimensions(self) -> list[str]:
        return ["alter_timeout", "reduce_test_subset"]

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="sql-state-diff-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="custom",
            guarantee=BackendGuaranteeDeclaration(
                type="state_diff",
                meaning_of_pass="Observed SQLite state difference matches the declared expectation.",
                meaning_of_fail="Observed SQLite state difference violates the declared expectation.",
                meaning_of_unknown="DB fixtures missing or unsupported configuration.",
            ),
            input_languages=["sql", "json"],
            supported_domains=["assurance", "data"],
            supported_property_kinds=["state_diff"],
            assumptions=["Before/after SQLite fixtures are authoritative offline materials."],
            limits=["SQLite offline only in core CI; no live network DB mutation."],
            result_format="ovk.result.v1",
            timeout_behavior="unknown",
            assurance=AssuranceCapabilitySection(
                assurance_capable=True,
                verifier_identity=AssuranceVerifierIdentity(
                    verifier_id="ovk.assurance.sql_state_diff",
                    implementation_name="SqlStateDiffAdapter",
                    entry_point="ovk.adapters.assurance.sql_diff.SqlStateDiffAdapter",
                    pcs_profile_artifact_type="VerifierProfile.v1",
                ),
                decision_semantics=AssuranceDecisionSemantics(
                    decision_space=_DECISION_SPACE,  # type: ignore[arg-type]
                    guarantee_class=GUARANTEE_CLASS,  # type: ignore[arg-type]
                    supported_claim_ids=["claim.sql.state_diff"],
                    out_of_scope_claim_ids=["claim.formal.full_correctness"],
                ),
                mechanism_class="static_analysis",
                determinism="deterministic",
                evidence_channels=[
                    "raw_backend_result",
                    "normalized_result",
                    "state_diff",
                    "compiled_obligation",
                ],
                replay_support=AssuranceReplaySupport(
                    supported=True,
                    compares_raw_digest=True,
                    compares_normalized_digest=True,
                ),
                configuration_snapshot_support=AssuranceSnapshotSupport(
                    supported=True,
                    exports_pcs_profile=True,
                ),
                mutation_dimensions=self.supported_mutation_dimensions(),  # type: ignore[arg-type]
                abstention=AssuranceAbstention(allows_abstention=True),
                failure_behavior=AssuranceFailureBehavior(),
                external_dependencies=[],
                known_limits=["SQLite fixtures only"],
                requires_authoritative_state=True,
            ),
        )

    def snapshot_config(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> ConfigurationSnapshot:
        cfg = dict(config or {})
        cfg.setdefault("timeout_ms", self.timeout_ms)
        cfg.setdefault("expect_changed_tables", cfg.get("expect_changed_tables"))
        for key in ("before_db", "after_db"):
            if isinstance(cfg.get(key), str):
                cfg[key] = cfg[key].replace("\\", "/")
        return build_configuration_snapshot(
            backend_id=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            config=cfg,
            environment=environment,
            mechanism_class="static_analysis",
            determinism="deterministic",
            allows_abstention=True,
            guarantee_class=GUARANTEE_CLASS,
            decision_space=_DECISION_SPACE,
            supported_claim_ids=["claim.sql.state_diff"],
            out_of_scope_claim_ids=["claim.formal.full_correctness"],
            assumptions=["Offline SQLite before/after fixtures."],
            known_blind_spots=["Does not prove application-level invariants beyond table digests."],
            entry_point="ovk.adapters.assurance.sql_diff.SqlStateDiffAdapter",
            implementation_name="SqlStateDiffAdapter",
            timeout_ms=int(cfg["timeout_ms"]),
            mutation_dimensions=self.supported_mutation_dimensions(),
            extra={
                "before_db": cfg.get("before_db"),
                "after_db": cfg.get("after_db"),
            },
        )

    def run_assurance(
        self,
        *,
        input_data: Mapping[str, Any],
        snapshot: ConfigurationSnapshot,
        config: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        cfg = dict(snapshot.config)
        if config:
            cfg.update(dict(config))
        argv = [self.adapter_id, "sqlite-diff"]

        before_raw = input_data.get("before_db") or cfg.get("before_db")
        after_raw = input_data.get("after_db") or cfg.get("after_db")
        if not before_raw or not after_raw:
            return indeterminate_run_outcome(
                reason="missing_authoritative_state",
                message="before_db and after_db paths are required",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )
        before_recorded = str(before_raw).replace("\\", "/")
        after_recorded = str(after_raw).replace("\\", "/")
        before_path = Path(str(before_raw)).expanduser().resolve()
        after_path = Path(str(after_raw)).expanduser().resolve()
        if not before_path.is_file() or not after_path.is_file():
            return indeterminate_run_outcome(
                reason="missing_authoritative_state",
                message=f"SQLite fixtures missing: before={before_path.is_file()} after={after_path.is_file()}",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )

        tables = input_data.get("tables") or cfg.get("tables")
        table_list = [str(t) for t in tables] if isinstance(tables, list) else None
        try:
            diff = diff_sqlite(before_path, after_path, tables=table_list)
        except sqlite3.Error as exc:
            return indeterminate_run_outcome(
                reason="parser_failure",
                message=str(exc),
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )

        expect_unchanged = bool(input_data.get("expect_unchanged") or cfg.get("expect_unchanged"))
        expect_changed = input_data.get("expect_changed_tables")
        if expect_changed is None:
            expect_changed = cfg.get("expect_changed_tables")

        # Record caller-supplied paths (portable); resolve only for I/O and file digests.
        raw = {
            "before_db": before_recorded,
            "after_db": after_recorded,
            "before_file_digest": _file_digest(before_path),
            "after_file_digest": _file_digest(after_path),
            "diff": diff,
        }
        changed = list(diff.get("changed_tables") or [])
        if expect_unchanged:
            passed = len(changed) == 0 and not diff.get("schema_changed")
        elif isinstance(expect_changed, list):
            expected = sorted(str(t) for t in expect_changed)
            passed = sorted(changed) == expected
        else:
            # Default: any diff is informational reject unless expect_unchanged
            # Callers should declare expectation; missing expectation is unsupported.
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message="declare expect_unchanged=true or expect_changed_tables=[...]",
                raw_result=raw,
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )

        if passed:
            return accept_outcome(
                raw_result=raw,
                normalized_extra={"state_diff": diff},
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )
        return reject_outcome(
            raw_result=raw,
            normalized_extra={"state_diff": diff, "counterexamples": changed},
            stdout="reject: sql state diff mismatch",
            guarantee_class=GUARANTEE_CLASS,
            command_argv=argv,
        )
