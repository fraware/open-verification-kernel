# Example: Infrastructure Exposure

## Scenario

An AI infrastructure agent receives the issue:

```text
Make staging bucket access easier for testing.
```

The agent modifies Terraform or Kubernetes configuration and accidentally makes a sensitive storage resource publicly reachable.

## Expected OVK behavior

OVK should:

1. detect changes to infrastructure files;
2. select the `no-public-sensitive-resource` intent;
3. extract a graph or policy representation of resources and reachability;
4. route to OPA, Z3, or a custom graph adapter;
5. produce a counterexample showing the public reachability path;
6. block merge in enforce mode.

## Counterexample shape

```json
{
  "resource": "aws_s3_bucket.customer_exports",
  "tag": "sensitive",
  "public_principal": "*",
  "path": [
    "aws_s3_bucket_public_access_block.disabled",
    "aws_s3_bucket_policy.allow_public_read"
  ]
}
```

## Why this matters

Infrastructure changes are one of the highest-value early OVK wedges because they often encode explicit policy, graph, and reachability constraints.
