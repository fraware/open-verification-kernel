# Pull Request Assurance Review

The pull-request assurance review joins three distinct objects:

    Code Diff
    Guarantee Diff
    Assurance Diff

They answer different questions and deliberately remain separate.

## Code Diff

The Code Diff is the normalized set of repository files changed by the pull
request.

It does not itself imply that a guarantee changed or lost assurance.

## Guarantee Diff

The Guarantee Diff compares:

    trusted base guarantee manifest
    proposed head guarantee manifest

It describes governance edits such as added guarantees, removed guarantees,
machine-claim selector changes, dependency changes, and statement changes.

The proposed head manifest never becomes the current pull request's assurance
authority.

## Assurance Diff

The Assurance Diff compares admitted GuaranteeAssuranceSnapshot objects for the
base and head software revisions.

Both snapshots must have been evaluated against the same trusted active
guarantee definitions from the base manifest.

The review rejects a head snapshot whose guarantee-definition digests correspond
to the pull request's proposed guarantee manifest.

This prevents the invalid sequence:

    edit code
    weaken or retarget guarantee
    verify code against edited guarantee
    report preserved assurance

The valid sequence is:

    load trusted base guarantees
    evaluate base software under those guarantees
    evaluate head software under those same guarantees
    compare assurance states
    separately show proposed guarantee changes for review

## Typical review

For a pull request that edits application code and also proposes a guarantee
selector change, the review can report:

    Code Diff
      src/billing.py
      .verification/guarantees.json

    Guarantee Diff
      G-REFUND machine_claim changed

    Assurance Diff
      G-REFUND established -> established
      evidence fresh

The assurance result is still about the trusted base definition of G-REFUND.
The proposed selector becomes active only in a later revision once it is part of
the trusted base.

## Authority boundary

The review artifact is descriptive and content-addressed. It does not modify the
existing OVK merge decision lattice.

Normal ovk check already surfaces the Guarantee Diff automatically. Full
Assurance Diff rendering requires base and head admitted assurance snapshots;
the next integration step is feeding those snapshots from the supported
Protected Effect source pipeline into the ordinary pull-request path.
