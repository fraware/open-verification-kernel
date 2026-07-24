"""Post-freeze adjudication importer (VA-13).

Imports PCS adjudication references only after a campaign freeze marker is
present. Active/hidden holdout labels are never written into evidence packs,
logs, or verifier inputs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ovk.assurance.errors import AssuranceError
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.redaction import redact_mapping

HIDDEN_LABEL_KEYS = frozenset(
    {
        "hidden_label",
        "hidden_labels",
        "active_label",
        "active_labels",
        "holdout_label",
        "holdout_labels",
        "ground_truth_label",
        "ground_truth_labels",
        "formalpr_holdout_label",
        "label_private",
        "private_label",
    }
)

AUDIT_EVENT_TYPE = "ovk.assurance.adjudication_import.v1"


class AdjudicationImportError(AssuranceError):
    """Raised when adjudication import is refused."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _contains_hidden_labels(payload: Any, *, path: str = "$") -> list[str]:
    hits: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            key_l = str(key).strip().lower()
            child = f"{path}.{key}"
            if key_l in HIDDEN_LABEL_KEYS:
                hits.append(child)
            hits.extend(_contains_hidden_labels(value, path=child))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            hits.extend(_contains_hidden_labels(item, path=f"{path}[{index}]"))
    return hits


def load_freeze_marker(path: Path | str) -> dict[str, Any]:
    marker_path = Path(path)
    if not marker_path.is_file():
        raise AdjudicationImportError(f"freeze marker not found: {marker_path}")
    data = json.loads(marker_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AdjudicationImportError("freeze marker must be a JSON object")
    if data.get("frozen") is not True and str(data.get("status") or "").lower() != "frozen":
        raise AdjudicationImportError("freeze marker does not declare frozen=true/status=frozen")
    if not data.get("campaign_id"):
        raise AdjudicationImportError("freeze marker missing campaign_id")
    return data


def import_adjudication_reference(
    *,
    freeze_marker_path: Path | str,
    adjudication_ref: Mapping[str, Any],
    audit_log_path: Path | str | None = None,
    allow_hidden_labels: bool = False,
) -> dict[str, Any]:
    """Import a post-freeze adjudication reference with label isolation.

    ``allow_hidden_labels`` is always refused for production import paths; the
    parameter exists only so negative tests can assert the hard deny.
    """
    if allow_hidden_labels:
        raise AdjudicationImportError("allow_hidden_labels is permanently refused")

    freeze = load_freeze_marker(freeze_marker_path)
    payload = dict(adjudication_ref)
    leaks = _contains_hidden_labels(payload)
    if leaks:
        raise AdjudicationImportError(
            "adjudication reference contains forbidden hidden/active label fields: "
            + ", ".join(leaks[:10])
        )

    # Redact any accidental secret-looking fields; never copy label keys forward.
    cleaned, _ = redact_mapping(payload)
    for key in list(cleaned.keys()):
        if str(key).strip().lower() in HIDDEN_LABEL_KEYS:
            raise AdjudicationImportError(f"refused hidden label key after redaction: {key}")

    record = {
        "artifact_type": "OVKAdjudicationImport.v1",
        "imported_at": _utc_now_iso(),
        "campaign_id": freeze["campaign_id"],
        "freeze_marker_digest": sha256_digest(freeze),
        "adjudication_ref": cleaned,
        "adjudication_ref_digest": sha256_digest(cleaned),
        "label_isolation": {
            "hidden_labels_accessible": False,
            "active_labels_accessible": False,
            "written_to_evidence": False,
        },
    }

    event = {
        "event_type": AUDIT_EVENT_TYPE,
        "timestamp": record["imported_at"],
        "campaign_id": freeze["campaign_id"],
        "adjudication_ref_digest": record["adjudication_ref_digest"],
        "result": "accepted",
    }
    if audit_log_path is not None:
        path = Path(audit_log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    return record


def refuse_labels_in_verifier_input(input_data: Mapping[str, Any]) -> None:
    """Negative-path guard: refuse verifier inputs that embed holdout labels."""
    leaks = _contains_hidden_labels(input_data)
    if leaks:
        raise AdjudicationImportError(
            "verifier input must not embed hidden/active holdout labels: " + ", ".join(leaks[:10])
        )
