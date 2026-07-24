"""Optional stochastic model-judge assurance verifier (VA-11)."""

from __future__ import annotations

from typing import Any, Callable, Mapping, Protocol

from ovk.adapters.assurance._support import (
    AssuranceBackendMixin,
    accept_outcome,
    indeterminate_run_outcome,
    reject_outcome,
)
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

GUARANTEE_CLASS = "empirically_measured"

_DECISION_SPACE = [
    "accept",
    "reject",
    "indeterminate_execution_error",
    "indeterminate_out_of_scope",
    "indeterminate_insufficient_evidence",
]


class JudgeClient(Protocol):
    def judge(self, *, prompt: str, model: str, decoding: Mapping[str, Any], rubric: Mapping[str, Any]) -> dict[str, Any]:
        ...


class ContractFakeJudgeClient:
    """CI contract fake that exercises real adapter paths (no network).

    Deterministic given prompt/model/decoding/rubric; still labeled stochastic
    at the adapter level because production clients may be nondeterministic.
    """

    def judge(
        self,
        *,
        prompt: str,
        model: str,
        decoding: Mapping[str, Any],
        rubric: Mapping[str, Any],
    ) -> dict[str, Any]:
        material = {
            "prompt": prompt,
            "model": model,
            "decoding": dict(decoding),
            "rubric": dict(rubric),
        }
        digest = sha256_digest(material)
        # Stable pseudo-score in [0, 1] from digest bytes.
        score_int = int(digest.replace("sha256:", "")[:8], 16)
        score = (score_int % 1000) / 1000.0
        threshold_raw = rubric.get("threshold", "0.5")
        threshold = float(threshold_raw)
        # Canonical JSON forbids floats — emit score as decimal string.
        score_str = f"{score:.3f}"
        return {
            "provider": "contract_fake",
            "score": score_str,
            "passed": score >= threshold,
            "rationale": f"contract_fake score={score_str} threshold={threshold_raw}",
            "raw_response_digest": digest,
        }


def default_judge_client(kind: str | None = None) -> JudgeClient:
    resolved = (kind or "contract_fake").strip().lower()
    if resolved in {"contract_fake", "fake", "ci"}:
        return ContractFakeJudgeClient()
    if resolved in {"live", "network"}:
        raise FileNotFoundError(
            "live model-judge provider is opt-in and not configured "
            "(set judge_client=contract_fake for CI)"
        )
    raise FileNotFoundError(f"unknown model-judge client: {resolved}")


class ModelJudgeAdapter(AssuranceBackendMixin):
    """Stochastic model-judge; cannot upgrade guarantee class beyond empirical."""

    backend_id = "model-judge"
    adapter_id = "ovk-adapter-model-judge"
    adapter_version = "0.1.0"
    _guarantee_type = "model_judgment"

    def __init__(
        self,
        *,
        timeout_ms: int = 30_000,
        judge_client_factory: Callable[[str | None], JudgeClient] | None = None,
    ) -> None:
        self.timeout_ms = timeout_ms
        self._judge_client_factory = judge_client_factory or default_judge_client

    def supported_mutation_dimensions(self) -> list[str]:
        return ["alter_timeout", "change_rubric", "change_prompt", "change_threshold", "ensemble_quorum"]

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="model-judge-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="custom",
            guarantee=BackendGuaranteeDeclaration(
                type="model_judgment",
                meaning_of_pass="Model judge score met rubric threshold (empirical only).",
                meaning_of_fail="Model judge score missed rubric threshold.",
                meaning_of_unknown="Judge client missing, timed out, or unsupported input.",
            ),
            input_languages=["json", "text"],
            supported_domains=["assurance", "judgment"],
            supported_property_kinds=["model_judgment"],
            assumptions=["Judgments are stochastic/empirical; never formal."],
            limits=["Cannot upgrade guarantee class; live network is opt-in."],
            result_format="ovk.result.v1",
            timeout_behavior="unknown",
            assurance=AssuranceCapabilitySection(
                assurance_capable=True,
                verifier_identity=AssuranceVerifierIdentity(
                    verifier_id="ovk.assurance.model_judge",
                    implementation_name="ModelJudgeAdapter",
                    entry_point="ovk.adapters.assurance.model_judge.ModelJudgeAdapter",
                    pcs_profile_artifact_type="VerifierProfile.v1",
                ),
                decision_semantics=AssuranceDecisionSemantics(
                    decision_space=_DECISION_SPACE,  # type: ignore[arg-type]
                    guarantee_class=GUARANTEE_CLASS,  # type: ignore[arg-type]
                    supported_claim_ids=["claim.model_judge.empirical"],
                    out_of_scope_claim_ids=[
                        "claim.formal.full_correctness",
                        "claim.certificate_checked",
                        "claim.formally_checked",
                    ],
                ),
                mechanism_class="model_judge",
                determinism="stochastic",
                evidence_channels=[
                    "raw_backend_result",
                    "normalized_result",
                    "model_judgment",
                    "compiled_obligation",
                ],
                replay_support=AssuranceReplaySupport(
                    supported=True,
                    compares_raw_digest=False,
                    compares_normalized_digest=False,
                    notes="Stochastic; replay declares nondeterminism rather than matched digests.",
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
                        dependency_id="model-judge-client",
                        kind="service",
                        identity="model-judge",
                        optional=True,
                    )
                ],
                known_limits=["stochastic; cannot claim formal guarantees"],
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
        cfg.setdefault("model", cfg.get("model") or "contract-fake-v1")
        cfg.setdefault("judge_client", cfg.get("judge_client") or "contract_fake")
        cfg.setdefault("decoding", cfg.get("decoding") or {"temperature": "0", "max_tokens": 256})
        default_rubric = {"threshold": "0.5"}
        if not isinstance(cfg.get("rubric"), dict):
            cfg["rubric"] = dict(default_rubric)
        else:
            rubric = dict(cfg["rubric"])
            if "threshold" in rubric and isinstance(rubric["threshold"], float):
                rubric["threshold"] = format(rubric["threshold"], "f").rstrip("0").rstrip(".") or "0"
            rubric.setdefault("threshold", "0.5")
            cfg["rubric"] = rubric
        cfg.setdefault("prompt", cfg.get("prompt") or "")
        return build_configuration_snapshot(
            backend_id=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            config=cfg,
            environment=environment,
            model={"model": cfg.get("model"), "judge_client": cfg.get("judge_client")},
            prompt=cfg.get("prompt"),
            rubric=cfg.get("rubric"),
            threshold=(cfg.get("rubric") or {}).get("threshold") if isinstance(cfg.get("rubric"), dict) else None,
            mechanism_class="model_judge",
            determinism="stochastic",
            allows_abstention=True,
            guarantee_class=GUARANTEE_CLASS,
            decision_space=_DECISION_SPACE,
            supported_claim_ids=["claim.model_judge.empirical"],
            out_of_scope_claim_ids=["claim.formal.full_correctness", "claim.formally_checked"],
            assumptions=["Model judgments are empirical and may vary."],
            known_blind_spots=["Cannot upgrade to formally_checked."],
            external_dependencies=[
                {
                    "dependency_id": "model-judge-client",
                    "kind": "service",
                    "identity": str(cfg.get("judge_client")),
                    "optional": True,
                }
            ],
            entry_point="ovk.adapters.assurance.model_judge.ModelJudgeAdapter",
            implementation_name="ModelJudgeAdapter",
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
        argv = [self.adapter_id, "judge"]

        prompt = input_data.get("prompt")
        if prompt is None:
            prompt = cfg.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            # Allow subject text under input.subject
            subject = input_data.get("subject")
            if isinstance(subject, str) and subject.strip():
                prompt = subject
            else:
                return indeterminate_run_outcome(
                    reason="unsupported_input",
                    message="prompt or subject text is required",
                    guarantee_class=GUARANTEE_CLASS,
                    command_argv=argv,
                )

        model = str(input_data.get("model") or cfg.get("model") or "contract-fake-v1")
        decoding = dict(input_data.get("decoding") or cfg.get("decoding") or {})
        rubric = dict(input_data.get("rubric") or cfg.get("rubric") or {"threshold": "0.5"})
        if isinstance(rubric.get("threshold"), float):
            rubric["threshold"] = format(rubric["threshold"], "f").rstrip("0").rstrip(".") or "0"
        # Strip floats from decoding for digest stability.
        decoding_clean: dict[str, Any] = {}
        for key, value in decoding.items():
            if isinstance(value, float):
                decoding_clean[key] = format(value, "f").rstrip("0").rstrip(".") or "0"
            else:
                decoding_clean[key] = value
        decoding = decoding_clean
        client_kind = str(input_data.get("judge_client") or cfg.get("judge_client") or "contract_fake")

        try:
            client = self._judge_client_factory(client_kind)
        except FileNotFoundError:
            raise

        judgment = client.judge(prompt=prompt, model=model, decoding=decoding, rubric=rubric)
        # Ensure judgment payload is Canonical-JSON safe (no floats).
        if isinstance(judgment.get("score"), float):
            judgment = {**judgment, "score": format(judgment["score"], "f").rstrip("0").rstrip(".") or "0"}
        raw = {
            "prompt_digest": sha256_digest(prompt),
            "model": model,
            "decoding": decoding,
            "decoding_digest": sha256_digest(decoding),
            "rubric": rubric,
            "rubric_digest": sha256_digest(rubric),
            "judgment": judgment,
            "judge_client": client_kind,
            "seed": input_data.get("seed") or cfg.get("seed"),
        }
        # Hard invariant: never claim a stronger guarantee than empirical.
        if judgment.get("guarantee_class") in {"formally_checked", "certificate_checked", "human_reviewed"}:
            judgment = {**judgment, "guarantee_class": GUARANTEE_CLASS}

        if bool(judgment.get("passed")):
            return accept_outcome(
                raw_result=raw,
                normalized_extra={
                    "model_judgment": judgment,
                    "guarantee_class": GUARANTEE_CLASS,
                },
                stdout=str(judgment.get("rationale") or "accept"),
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )
        return reject_outcome(
            raw_result=raw,
            normalized_extra={
                "model_judgment": judgment,
                "counterexamples": [judgment],
                "guarantee_class": GUARANTEE_CLASS,
            },
            stdout=str(judgment.get("rationale") or "reject"),
            guarantee_class=GUARANTEE_CLASS,
            command_argv=argv,
        )
