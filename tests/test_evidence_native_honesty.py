from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.models import EvidenceBundle


def test_quality_gate_rejects_native_tool_claim_with_deterministic_assumptions() -> None:
    bundle = EvidenceBundle.model_validate(
        {
            "bundle_id": "bundle-test-native-honesty",
            "schema_version": "ovk.evidence.v1",
            "subject": {"repo": "test/repo", "head_sha": "abc12345"},
            "decision": {"merge_recommendation": "allow"},
            "evidence": [
                {
                    "evidence_id": "ev-native-honesty",
                    "subject": {"repo": "test/repo", "head_sha": "abc12345"},
                    "intent": {"intent_id": "cbmc-harness-check", "risk": {"severity": "low"}},
                    "backend_claims": [
                        {
                            "backend": "cbmc",
                            "guarantee_type": "native_tool",
                            "status": "pass",
                            "assumptions": [
                                "cbmc adapter uses deterministic fallback when binary is absent.",
                                "cbmc deterministic oracle result used.",
                            ],
                            "limits": ["oracle only"],
                            "adapter_version": "0.1.0",
                        }
                    ],
                    "decision": {"merge_recommendation": "allow"},
                    "generated_artifacts": [{"kind": "input_digest", "digest": "abc"}],
                }
            ],
        }
    )
    report = build_evidence_quality_report(bundle)
    assert report.passed is False
    messages = " ".join(issue.message for issue in report.issues)
    assert "OVK-INV-NATIVE-HONESTY" in messages
