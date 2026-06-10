from pathlib import Path

from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.json_io import read_json_file
from ovk.core.models import EvidenceBundle


def test_adversarial_bundle_fails_quality_gate() -> None:
    bundle = EvidenceBundle.model_validate(
        read_json_file(Path("examples/evidence_quality/adversarial_allow_with_fail.json"))
    )
    report = build_evidence_quality_report(bundle)
    assert report.passed is False
    messages = {issue.message for issue in report.issues}
    assert any("failing backend claim must not produce allow recommendation" in message for message in messages)
    assert any("bundle with invariant errors must not recommend allow" in message for message in messages)
