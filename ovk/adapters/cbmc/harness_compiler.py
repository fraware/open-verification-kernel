"""Compile CBMC harnesses for data-boundary intent templates."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from ovk.paths import resource_path

CBMC_TEMPLATE_IDS = frozenset(
    {
        "cbmc-harness-check",
        "cbmc-buffer-bounds",
        "cbmc-no-integer-overflow-quota",
        "cbmc-no-unchecked-buffer-copy",
        "cbmc-no-use-after-free-auth-cache",
    }
)

_TEMPLATE_TO_FIXTURE_STEM = {
    "cbmc-harness-check": "buffer_bounds",
    "cbmc-buffer-bounds": "buffer_bounds",
    "cbmc-no-integer-overflow-quota": "integer_overflow_quota",
    "cbmc-no-unchecked-buffer-copy": "unchecked_buffer_copy",
    "cbmc-no-use-after-free-auth-cache": "use_after_free_auth_cache",
}

_HARNESS_ROOT = resource_path("examples", "backends", "cbmc_harness")


def _resolve_existing_harness(data: dict[str, Any]) -> Path | None:
    harness_path = data.get("harness_path")
    if not harness_path:
        return None
    path = Path(str(harness_path))
    if path.is_file():
        return path.resolve()
    packaged_fixture = _HARNESS_ROOT / path.name
    if packaged_fixture.is_file():
        return packaged_fixture.resolve()
    return None


def _fixture_harness_path(intent_id: str, *, expect_pass: bool) -> Path | None:
    stem = _TEMPLATE_TO_FIXTURE_STEM.get(intent_id)
    if stem is None:
        return None
    suffix = "pass" if expect_pass else "fail"
    path = _HARNESS_ROOT / f"{stem}_{suffix}.c"
    return path if path.is_file() else None


def _generated_buffer_bounds_harness(data: dict[str, Any]) -> str:
    buffer_size = int(data.get("buffer_size", 16))
    expect_violation = bool(data.get("expect_violation", data.get("failed_assertions")))
    guard = "" if expect_violation else f"  __CPROVER_assume(index < {buffer_size});\n"
    return f"""#include <assert.h>
#include <stdint.h>

#define BUFFER_SIZE {buffer_size}

void harness(void) {{
    uint8_t buffer[BUFFER_SIZE];
    unsigned int index;
{guard}    buffer[index] = 0x41U;
    assert(index < BUFFER_SIZE);
}}
"""


def _generated_integer_overflow_harness(data: dict[str, Any]) -> str:
    quota_limit = int(data.get("quota_limit", 1000))
    expect_violation = bool(data.get("expect_violation", data.get("failed_assertions")))
    guard = ""
    if not expect_violation:
        guard = f"  __CPROVER_assume(used <= {quota_limit});\n  __CPROVER_assume(delta <= {quota_limit} - used);\n"
    return f"""#include <assert.h>
#include <stdint.h>

#define QUOTA_LIMIT {quota_limit}

void harness(void) {{
    unsigned int used;
    unsigned int delta;
{guard}    unsigned int next = used + delta;
    assert(next >= used);
    assert(next <= QUOTA_LIMIT);
}}
"""


def _generated_unchecked_copy_harness(data: dict[str, Any]) -> str:
    buffer_size = int(data.get("buffer_size", 32))
    expect_violation = bool(data.get("expect_violation", data.get("failed_assertions")))
    guard = "" if expect_violation else f"  __CPROVER_assume(length <= {buffer_size});\n"
    return f"""#include <assert.h>
#include <stdint.h>
#include <string.h>

#define DEST_SIZE {buffer_size}

void harness(void) {{
    uint8_t dest[DEST_SIZE];
    uint8_t src[DEST_SIZE];
    unsigned int length;
{guard}    memcpy(dest, src, length);
    assert(length <= DEST_SIZE);
}}
"""


def _generated_use_after_free_harness(data: dict[str, Any]) -> str:
    expect_violation = bool(data.get("expect_violation", data.get("failed_assertions")))
    if expect_violation:
        body = """    int *entry = (int *)malloc(sizeof(int));
    free(entry);
    *entry = 1;
    assert(entry != NULL);"""
    else:
        body = """    int *entry = (int *)malloc(sizeof(int));
    assert(entry != NULL);
    *entry = 1;
    free(entry);
    entry = NULL;
    assert(entry == NULL);"""
    return f"""#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

void harness(void) {{
{body}
}}
"""


_GENERATORS = {
    "cbmc-harness-check": _generated_buffer_bounds_harness,
    "cbmc-buffer-bounds": _generated_buffer_bounds_harness,
    "cbmc-no-integer-overflow-quota": _generated_integer_overflow_harness,
    "cbmc-no-unchecked-buffer-copy": _generated_unchecked_copy_harness,
    "cbmc-no-use-after-free-auth-cache": _generated_use_after_free_harness,
}


def default_unwind_for_intent(intent_id: str) -> int:
    """Return a conservative unwind bound for a CBMC template."""
    if intent_id == "cbmc-no-integer-overflow-quota":
        return 32
    if intent_id == "cbmc-no-use-after-free-auth-cache":
        return 8
    return 16


def compile_cbmc_harness(
    data: dict[str, Any],
    *,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Resolve or generate a CBMC harness for obligation input data."""
    intent_id = str(data.get("intent_id", "cbmc-harness-check"))
    if intent_id not in CBMC_TEMPLATE_IDS:
        raise ValueError(f"unsupported CBMC intent for harness compilation: {intent_id}")

    existing = _resolve_existing_harness(data)
    if existing is not None:
        return {
            **data,
            "intent_id": intent_id,
            "harness_path": str(existing),
            "harness_origin": "explicit",
            "entry_function": str(data.get("entry_function", "harness")),
            "unwind": int(data.get("unwind", default_unwind_for_intent(intent_id))),
        }

    expect_pass = not bool(data.get("failed_assertions") or data.get("expect_violation"))
    fixture = _fixture_harness_path(intent_id, expect_pass=expect_pass)
    if fixture is not None and not data.get("force_generate"):
        return {
            **data,
            "intent_id": intent_id,
            "harness_path": str(fixture),
            "harness_origin": "fixture",
            "entry_function": "harness",
            "unwind": int(data.get("unwind", default_unwind_for_intent(intent_id))),
        }

    generator = _GENERATORS[intent_id]
    source = generator(data)
    target_dir = output_dir or Path(tempfile.mkdtemp(prefix="ovk-cbmc-"))
    target_dir.mkdir(parents=True, exist_ok=True)
    harness_path = target_dir / f"{intent_id.replace('-', '_')}.c"
    harness_path.write_text(source, encoding="utf-8")
    return {
        **data,
        "intent_id": intent_id,
        "harness_path": str(harness_path),
        "harness_origin": "generated",
        "entry_function": "harness",
        "unwind": int(data.get("unwind", default_unwind_for_intent(intent_id))),
        "generated": True,
    }


def obligation_has_runnable_harness(data: dict[str, Any]) -> bool:
    """Return True when input data can be compiled to a runnable CBMC harness."""
    intent_id = str(data.get("intent_id", ""))
    if intent_id not in CBMC_TEMPLATE_IDS:
        return False
    if _resolve_existing_harness(data) is not None:
        return True
    if _fixture_harness_path(intent_id, expect_pass=True) is not None:
        return True
    if _fixture_harness_path(intent_id, expect_pass=False) is not None:
        return True
    return intent_id in _GENERATORS
