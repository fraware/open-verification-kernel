# Rationale: `rd_infra_s3_public_acl`

- Partition: `test`
- Category: `real_diff`
- Expected decision signal: `block`

## Why this expectation

End-to-end `ovk check` on a sanitized agent-style PR diff must recall the listed intents/lanes and emit the expected merge recommendation.

## Non-claims

This case does not claim complete application security or solver completeness.
