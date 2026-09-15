# Integrator Hardcode Evidence

Use when a worker or integration review identifies a `replay-isolation`
public-domain finding. Inspect source and prepare exact evidence in the assigned
worktree, then repeat that worktree's `review check` with the proven mappings.
Report acceptance and traffic verification remain coordinator-owned.

All added Rust lines, including tests, reject `.trp.test`. Other Replay-private
markers remain prohibited in production paths. Only the public-domain rules for
`sample.test` and `demo.test` accept the source-proof exception below. This is
not an exemption for private Replay values.

Prove that the same value is hardcoded in source code. Traffic, recordings,
logs, runtime configuration, and container state are not source proof.
Inspect the exact source revision and target occurrence. Return the narrow
source fact and one mapping per finding.

The target occurrence must be committed at its exact position. Record one
commit trailer per occurrence in the candidate history:

```text
Hardcode-Source-Evidence: TARGET_FILE:LINE:COLUMN <= SOURCE_REPOSITORY@SOURCE_REVISION:SOURCE_FILE:LINE:COLUMN
```

`SOURCE_REVISION` is the inspected 7-64 hexadecimal commit ID. Preserve product
content while preparing a missing evidence trailer on the assigned base; keep
already committed target positions valid. `TARGET_FILE` is relative to the
target and may begin with a configured managed
sibling path such as `../backend-rs/`; use the exact path reported by the gate.
Return the candidate commit and the exact corresponding mappings:

```text
TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@SOURCE_REVISION:SOURCE_FILE:LINE:COLUMN
```

Supply each mapping through a separate `review check --hardcode-ai-verified`
argument. A changed target location requires a newly current mapping and report.

Missing, duplicate, stale, unrelated, or uncommitted positions fail the gate.
Do not relabel unknown provenance as source-proven. Return unproven occurrences
as findings for their responsible implementation owner.
