"""PCS pin digest enforcement."""

from __future__ import annotations

import pytest

from ovk.assurance.errors import PinError
from ovk.assurance.pin import (
    EXPECTED_SCHEMA_DIGESTS,
    PCS_PIN_COMMIT,
    load_schema_digests,
    resolve_pcs_root,
    verify_pin_digests,
)


@pytest.mark.skipif(resolve_pcs_root() is None, reason="PCS pin unavailable")
def test_pin_digests_match_documented_table() -> None:
    actual = verify_pin_digests()
    assert actual["VerifierProfile.v1"] == EXPECTED_SCHEMA_DIGESTS["VerifierProfile.v1"]
    assert actual["VerifierInvocationRecord.v1"] == EXPECTED_SCHEMA_DIGESTS[
        "VerifierInvocationRecord.v1"
    ]
    assert PCS_PIN_COMMIT.startswith("fb588a41")


@pytest.mark.skipif(resolve_pcs_root() is None, reason="PCS pin unavailable")
def test_pin_digest_drift_fails_closed() -> None:
    bad = dict(EXPECTED_SCHEMA_DIGESTS)
    bad["VerifierProfile.v1"] = "sha256:" + ("0" * 64)
    with pytest.raises(PinError, match="digest drift"):
        verify_pin_digests(expected=bad)
    # Cache may retain good digests; ensure load still works.
    assert load_schema_digests()["VerifierProfile.v1"].startswith("sha256:")
