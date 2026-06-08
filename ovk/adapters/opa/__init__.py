"""OPA-style adapter package.

The first implementation includes a deterministic Python evaluator for the
self-protection policy so CI and demos do not depend on a local OPA binary.
The Rego policy lives under ``adapters/opa/policies/`` and should be wired to
OPA CLI execution in the next adapter hardening pass.
"""

from ovk.adapters.opa.self_protection import evaluate_self_protection

__all__ = ["evaluate_self_protection"]
