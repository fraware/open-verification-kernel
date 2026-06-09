# Sprint 3 Validation Coverage Update

The authorization validation test suite has been expanded.

New cases covered:

- missing route path;
- missing `reachable_after` list;
- non-object witness entries;
- empty route lists;
- non-object route entries;
- non-boolean route flags;
- malformed witness roles and `via` values.

The safety rule remains unchanged: malformed authorization abstractions are insufficient evidence and must require review instead of producing an allow recommendation.
