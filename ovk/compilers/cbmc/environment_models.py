"""Environment models declared for CBMC runs."""

from __future__ import annotations

DEFAULT_ENVIRONMENT_MODELS = (
    "nondet_inputs",
    "bounded_loops",
    "havoc_external_apis",
)


def select_environment_models(*, include_posix: bool = False) -> list[str]:
    models = list(DEFAULT_ENVIRONMENT_MODELS)
    if include_posix:
        models.append("posix_stubs")
    return models
