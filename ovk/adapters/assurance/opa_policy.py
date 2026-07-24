"""OPA policy assurance verifier (VA-08) — real ``opa eval`` only."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from shutil import which
from typing import Any, Mapping

from ovk.adapters.assurance._support import (
    AssuranceBackendMixin,
    accept_outcome,
    indeterminate_run_outcome,
    reject_outcome,
)
from ovk.adapters.opa.optional_runner import run_opa_policy
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.snapshot import ConfigurationSnapshot, build_configuration_snapshot
from ovk.core.execution_models import (
    AssuranceAbstention,
    AssuranceCapabilitySection,
    AssuranceDecisionSemantics,
    AssuranceExternalDependency,
    AssuranceFailureBehavior,
    AssuranceReplaySupport,
    AssuranceSnapshotSupport,
    AssuranceVerifierIdentity,
    BackendCapabilityManifest,
    BackendGuaranteeDeclaration,
    BackendToolIdentity,
)

GUARANTEE_CLASS = "certificate_checked"

_DECISION_SPACE = [
    "accept",
    "reject",
    "indeterminate_execution_error",
    "indeterminate_out_of_scope",
    "indeterminate_insufficient_evidence",
]


class OpaPolicyAssuranceAdapter(AssuranceBackendMixin):
    """Assurance-capable OPA policy verifier using real ``opa eval``.

    Distinct from ordinary ``opa-native`` lane routing. Missing ``opa`` binary
    yields typed indeterminate (never fabricated pass). Cedar is not involved.
    """

    backend_id = "opa-policy"
    adapter_id = "ovk-adapter-opa-policy-assurance"
    adapter_version = "0.1.0"
    _guarantee_type = "policy_evaluation"

    def __init__(self, *, timeout_ms: int = 15_000) -> None:
        self.timeout_ms = timeout_ms

    def supported_mutation_dimensions(self) -> list[str]:
        return ["alter_timeout", "policy_bundle"]

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="opa-policy-assurance-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="policy_engine",
            guarantee=BackendGuaranteeDeclaration(
                type="policy_evaluation",
                meaning_of_pass="opa eval reported no violations for the pinned policy/query.",
                meaning_of_fail="opa eval reported one or more violations.",
                meaning_of_unknown="opa binary missing, timed out, or returned invalid output.",
            ),
            input_languages=["json", "rego"],
            supported_domains=["assurance", "policy"],
            supported_property_kinds=["policy_evaluation", "invariant"],
            assumptions=["Rego policy and query are pinned in the configuration snapshot."],
            limits=["Requires opa; never falls back to Cedar or deterministic fake pass."],
            result_format="ovk.result.v1",
            counterexample_format="policy_violation",
            timeout_behavior="unknown",
            assurance=AssuranceCapabilitySection(
                assurance_capable=True,
                verifier_identity=AssuranceVerifierIdentity(
                    verifier_id="ovk.assurance.opa_policy",
                    implementation_name="OpaPolicyAssuranceAdapter",
                    entry_point="ovk.adapters.assurance.opa_policy.OpaPolicyAssuranceAdapter",
                    pcs_profile_artifact_type="VerifierProfile.v1",
                ),
                decision_semantics=AssuranceDecisionSemantics(
                    decision_space=_DECISION_SPACE,  # type: ignore[arg-type]
                    guarantee_class=GUARANTEE_CLASS,  # type: ignore[arg-type]
                    supported_claim_ids=["claim.opa.policy_evaluation"],
                    out_of_scope_claim_ids=["claim.formal.full_correctness"],
                ),
                mechanism_class="policy_engine",
                determinism="deterministic",
                evidence_channels=[
                    "stdout",
                    "stderr",
                    "raw_backend_result",
                    "normalized_result",
                    "counterexample",
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
                external_dependencies=[
                    AssuranceExternalDependency(
                        dependency_id="opa",
                        kind="binary",
                        identity="opa",
                        optional=False,
                    )
                ],
                known_limits=["Requires local opa binary; Cedar is never used."],
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
        cfg.setdefault("query", cfg.get("query") or "data.ovk.assurance.allow")
        policy_text = cfg.get("policy")
        policy_path = cfg.get("policy_path")
        policy_material: Any
        if isinstance(policy_text, str) and policy_text.strip():
            policy_material = {"inline": policy_text}
        elif policy_path:
            policy_material = {"path": str(policy_path)}
        else:
            policy_material = {"path": None}
        return build_configuration_snapshot(
            backend_id=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            config=cfg,
            environment=environment,
            policy=policy_material,
            mechanism_class="policy_engine",
            determinism="deterministic",
            allows_abstention=True,
            guarantee_class=GUARANTEE_CLASS,
            decision_space=_DECISION_SPACE,
            supported_claim_ids=["claim.opa.policy_evaluation"],
            out_of_scope_claim_ids=["claim.formal.full_correctness"],
            assumptions=["Real opa eval only; missing opa is indeterminate."],
            known_blind_spots=["Does not evaluate Cedar policies."],
            external_dependencies=[
                {"dependency_id": "opa", "kind": "binary", "identity": "opa", "optional": False}
            ],
            entry_point="ovk.adapters.assurance.opa_policy.OpaPolicyAssuranceAdapter",
            implementation_name="OpaPolicyAssuranceAdapter",
            timeout_ms=int(cfg["timeout_ms"]),
            mutation_dimensions=self.supported_mutation_dimensions(),
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
        command_argv = ["opa", "eval", str(cfg.get("query") or "data.ovk.assurance.allow")]

        if which("opa") is None:
            raise FileNotFoundError("opa binary not found")

        policy_text = input_data.get("policy") or cfg.get("policy")
        policy_path_raw = input_data.get("policy_path") or cfg.get("policy_path")
        query = str(input_data.get("query") or cfg.get("query") or "data.ovk.assurance.allow")
        opa_input = input_data.get("input")
        if opa_input is None:
            opa_input = {k: v for k, v in input_data.items() if k not in {"policy", "policy_path", "query"}}
        if not isinstance(opa_input, Mapping):
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message="OPA input must be a JSON object",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=command_argv,
            )

        timeout_ms = int(cfg.get("timeout_ms") or self.timeout_ms)
        with tempfile.TemporaryDirectory(prefix="ovk-opa-assurance-") as tmp:
            tmp_path = Path(tmp)
            if isinstance(policy_text, str) and policy_text.strip():
                policy_file = tmp_path / "policy.rego"
                policy_file.write_text(policy_text, encoding="utf-8")
                policy_digest = sha256_digest(policy_text)
            elif policy_path_raw:
                policy_file = Path(str(policy_path_raw)).expanduser().resolve()
                if not policy_file.is_file():
                    return indeterminate_run_outcome(
                        reason="unsupported_input",
                        message=f"policy_path not found: {policy_file}",
                        guarantee_class=GUARANTEE_CLASS,
                        command_argv=command_argv,
                    )
                policy_digest = sha256_digest(policy_file.read_text(encoding="utf-8"))
            else:
                return indeterminate_run_outcome(
                    reason="unsupported_input",
                    message="policy or policy_path is required",
                    guarantee_class=GUARANTEE_CLASS,
                    command_argv=command_argv,
                )

            input_file = tmp_path / "input.json"
            input_file.write_text(json.dumps(dict(opa_input), sort_keys=True), encoding="utf-8")
            command_argv = [
                "opa",
                "eval",
                "--format",
                "json",
                "--data",
                str(policy_file),
                "--input",
                str(input_file),
                query,
            ]
            result = run_opa_policy(
                policy_path=policy_file,
                input_path=input_file,
                query=query,
                timeout_seconds=max(int(timeout_ms / 1000), 1),
                cwd=tmp_path,
            )

        raw = {
            "opa_result": result,
            "policy_digest": policy_digest,
            "query": query,
            "input_digest": sha256_digest(dict(opa_input)),
        }
        status = str(result.get("status") or "")
        if status == "unknown" and "not found" in str(result.get("reason") or "").lower():
            raise FileNotFoundError(str(result.get("reason") or "opa binary not found"))
        if status == "unknown" and "timed out" in str(result.get("reason") or "").lower():
            raise TimeoutError(str(result.get("reason") or "opa timed out"))
        if status == "error":
            return indeterminate_run_outcome(
                reason="parser_failure",
                message=str(result.get("reason") or "opa error"),
                raw_result=raw,
                guarantee_class=GUARANTEE_CLASS,
                command_argv=command_argv,
            )
        if status == "unknown":
            return indeterminate_run_outcome(
                reason="other",
                message=str(result.get("reason") or "opa unknown"),
                raw_result=raw,
                guarantee_class=GUARANTEE_CLASS,
                command_argv=command_argv,
            )
        violations = list(result.get("violations") or [])
        # For allow-style queries, empty/false means reject when query value is boolean false.
        if status == "pass" and not violations:
            return accept_outcome(
                raw_result=raw,
                normalized_extra={"violations": [], "policy_digest": policy_digest},
                guarantee_class=GUARANTEE_CLASS,
                command_argv=command_argv,
            )
        return reject_outcome(
            raw_result=raw,
            normalized_extra={"counterexamples": violations, "violations": violations, "policy_digest": policy_digest},
            stdout="reject: opa violations",
            guarantee_class=GUARANTEE_CLASS,
            command_argv=command_argv,
        )
