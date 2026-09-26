# Semantic Authorization v2 development cases

These public development cases exercise production-shaped source profiles.

The first case models a FastAPI route where authorization is performed by a
dependency and the protected resource is later fetched through a service call.
It is derived from a public GitHub-reviewed advisory and is therefore explicitly
high contamination risk. It is useful for product regression testing, not for
claims about contamination-free generalization.

The central property is:

    authorized route scope == acted resource scope

The secure and vulnerable variants differ only in whether the protected service
lookup receives the authorized workspace scope.
