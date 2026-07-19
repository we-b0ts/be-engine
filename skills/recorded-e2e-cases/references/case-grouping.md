# Case Group Selection

Use this workflow before business-implementation analysis when a supplied
collection or run contains more than one canonical case directory. The goal is
to process exactly one source API group at a time without changing published
recordings.

## Incremental Selection

1. Select one unprocessed canonical input directory. Ignore `failed`,
   `staging`, `.replay`, `.partial`, `.truncated`, and derived group artifacts.
2. Read the first published case only to identify a candidate API. Match its
   HTTP method and URI path without the query component against source route
   registrations. Route discovery is allowed here; do not inspect business
   implementation details or modify product code yet.
3. When the source route is exact and static, run `traffic-e2e prepare`
   without `--pattern`. Its canonical grouping operation MUST inspect every
   published case in the directory, require every method and path to resolve to
   that same source route, return the current directory as `group_dir`, and
   record `already_canonical` with its exact case ids. A mixed-route directory
   is `blocked_grouping`.
4. When the source route is dynamic, derive the candidate recorder pattern by
   following [route-pattern-feedback.md](route-pattern-feedback.md), then run
   `traffic-e2e prepare` with the original case source, current directory,
   method, confirmed source route, pattern, and source revision. The runner
   supplies managed recorder config and the persisted index path. Use only the
   returned group directory or manifest and exact case ids.
5. Mark every returned member directory processed. A later prepare for any member
   MUST return the same group with `already_grouped`; process the group exactly
   once. Never infer grouping state from a directory name or hand-written
   marker.
6. Inspect and migrate the selected group only after grouping reaches a valid
   terminal result. Focused migration may proceed before every other API is
   grouped, but the full round is blocked until every published case is covered
   exactly once.

The first case is a route-discovery sample, not evidence that the whole
directory is homogeneous. The exact selected case ids come from the complete
group validation.

## Required Invocation

Use one runner-owned persisted index for the whole original case source and
source revision. For a standard migration, run the static form:

```bash
traffic-e2e prepare \
  --target-root <target-repository> \
  --case-source <original-case-source> \
  --case-dir <current-canonical-directory> \
  --method <METHOD> \
  --source-route '<confirmed-static-source-route>' \
  --source-revision '<source-revision>'
```

For a dynamic source route, add the confirmed pattern:

```bash
traffic-e2e prepare \
  --target-root <target-repository> \
  --case-source <original-case-source> \
  --case-dir <current-canonical-directory> \
  --method <METHOD> \
  --source-route '<confirmed-dynamic-source-route>' \
  --pattern '<safe-recorder-path-pattern>' \
  --source-revision '<source-revision>'
```

The runner reads `recorder_config` and `recording_rule` from
`.traffic-e2e/e2e.yaml`; they MUST appear together. Omit both only when the
managed target config is unavailable, and retain the returned
`not_applicable_missing_managed_config` outcome. The command applies focused,
add-only pattern feedback when both are present. This early apply does not waive
the final plan/apply/replan gate.

## Canonical Tool Contract

Accept only `created`, `already_grouped`, or `already_canonical` as successful
grouping results. A new dynamic group MUST return `created`, a repeat from any
of its member directories MUST return `already_grouped`, and a static group
MUST return `already_canonical`. Require canonical output to include:

- status and stable group id
- method and resolved source route
- route pattern and pattern outcome when dynamic
- returned group directory or manifest
- exact case ids and every member input directory
- source revision and case-inventory identity
- persisted JSON report path

Treat missing commands, mixed or unmatched routes, ambiguous patterns,
overlapping groups, missing cases, duplicate case ids, stale group inventory,
or a changed source revision as `blocked_grouping`. Do not replace the command
with an AI-authored target script or a hand-maintained case list.

`traffic-e2e prepare` delegates to
`traffic-e2e diagnose case-group ensure`; direct low-level invocation is for
diagnostics, not the normal AI workflow. Dynamic groups are manifest-backed:
`group_dir` may be absent, in which case the returned manifest and exact case
ids are the only valid replay selection. Do not invent a directory path.
`traffic-e2e diagnose case-group` may orchestrate the managed pattern plan and
safe apply, but its result does not replace the final recorder-config
plan/apply/replan evidence gate.

## Immutability

MUST NOT move, rename, copy, delete, or edit published case directories during
grouping. Derived group artifacts must reference the original cases and live
outside the canonical case source. A future materialization mode requires
separate explicit user authorization and is not part of this workflow.

For a multi-group task, completion additionally requires every selected case id
to occur in exactly one group, every group to reach a terminal state, and the
final aggregate to cover the exact completion case set. A blocker is a valid
terminal state for ending work on one group, but it leaves the parent collection
or run incomplete and cannot be counted as a passed group.
