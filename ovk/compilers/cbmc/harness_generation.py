"""CBMC harness generation with explicit project-code inclusion flags."""

from __future__ import annotations

from ovk.compilers.cbmc.project import CbmcFunctionTarget, CbmcHarness


def generate_harness(
    target: CbmcFunctionTarget,
    *,
    obligation_id: str | None = None,
    intent_id: str | None = None,
    bound: int = 10,
    includes_project_code: bool = False,
) -> CbmcHarness:
    """Generate a harness descriptor.

    ``includes_project_code`` must be True only when the harness actually links
    or inlines project translation units. Callers must not set this flag for
    stub-only harnesses.
    """
    return CbmcHarness(
        harness_id=f"harness-{target.name}",
        entry_function=f"harness_{target.name}",
        source_path=None if not includes_project_code else target.file,
        traces_to_obligation_id=obligation_id,
        traces_to_intent_id=intent_id,
        traces_to_source_functions=[target.name],
        bound=bound,
        includes_project_code=includes_project_code,
    )


def render_harness_stub(harness: CbmcHarness) -> str:
    includes = f'#include "{harness.source_path}"\n' if harness.includes_project_code and harness.source_path else ""
    return (
        f"/* harness_id={harness.harness_id} "
        f"obligation={harness.traces_to_obligation_id} "
        f"intent={harness.traces_to_intent_id} */\n"
        f"{includes}"
        f"void {harness.entry_function}(void);\n"
        f"int main(void) {{ {harness.entry_function}(); return 0; }}\n"
    )
