"""Z3-style adapter package.

The first implementation provides a small deterministic reachability checker for
authorization fixtures. It models the same shape that the future Z3-backed
implementation should encode: a non-admin principal reaching an admin-only route
is a counterexample.
"""

from ovk.adapters.z3.authorization import evaluate_authorization_reachability

__all__ = ["evaluate_authorization_reachability"]
