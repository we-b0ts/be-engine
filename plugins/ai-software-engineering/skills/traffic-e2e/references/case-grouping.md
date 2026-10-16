# Traffic E2E Case Group Selection

Use this workflow before business-implementation analysis when a supplied
collection or run contains more than one canonical case directory. The goal is
to process exactly one source API group at a time without changing published
recordings.

## Contents

- Incremental selection
- Required invocation
- Canonical tool contract
- Immutability

## Incremental Selection

1. Select one unprocessed canonical input directory. Ignore `failed`,
   `staging`, `.replay`, `.partial`, `.truncated`, and derived group artifacts.
2. Read the first published case only to identify a candidate API. Match its
   HTTP method and URI path without the query component against source route
   registrations. Route discovery is allowed here; do not inspect business
   implementation details or modify product code yet.
3. Prepare the selected `METHOD API` against the original case source. The
   engine inspects all published request metadata and selects only cases whose
   method and URI path match that exact route or confirmed pattern. A registered
   static route is excluded from its same-method wildcard. Different methods of
   one canonical route may share a physical recording directory.
4. For a dynamic route, supply the source-proven pattern with `--pattern`.
   For a static route, omit it. A homogeneous static directory may return
   `already_canonical` with `group_dir`; a shared or multi-directory static
   selection returns a manifest-backed `created` group with exact case IDs.
5. Mark returned case IDs and the logical `METHOD API` processed. A physical
   member directory may still contain another method of the same route to prepare.
   Repeating the same group from a member returns `already_grouped` for a
   manifest group, or `already_canonical` for a whole static directory.
6. Inspect or verify the selected group only after grouping reaches a valid
   terminal result. Focused verification may proceed before every other API is
   grouped, but the full round cannot advance until every published case is
   covered exactly once.

The first case is a route-discovery sample, not evidence that the whole
directory is homogeneous. Sharing is allowed only for methods of the same
confirmed canonical API; a mixed static/pattern directory is rejected.
The exact selected case IDs come from complete group validation. Version-three
indexes persist the method-specific registry; version-one/two execution is
unsupported. Finish historical Replay with its original engine before upgrading.

Discovery retains valid recorded HTTP paths exactly, including trailing slashes
and repeated separators. Such a path must not block preparation of an unrelated
canonical API. Source-route and pattern selectors retain their canonical
separator requirements: discovery never trims or aliases recorded paths to make
them match. Unselected cases remain in the inventory and still require explicit
coverage before a full round can advance.

## Required Invocation

Use one runner-owned persisted index for the whole original case source and
source revision. For the standard workflow, run the static form:

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

The runner reads the merged recorder section from `.traffic-e2e/project.yaml`;
the global HTTP feedback is resolved from `.traffic-e2e/source-traffic-policy.yaml`
without selecting a recording rule. Omit managed feedback only when the
managed target config is unavailable, and retain the returned
`not_applicable_missing_managed_config` outcome. The command applies focused,
add-only pattern feedback when both are present. This early apply does not waive
the final plan/apply/replan gate.

## Canonical Tool Contract

Accept only `created`, `already_grouped`, or `already_canonical` as successful
grouping results. A new dynamic group MUST return `created`, a repeat from any
of its member directories MUST return `already_grouped`, and a static group
returns `already_canonical` only when the whole directory is that group; otherwise it is manifest-backed and returns `created`. Require canonical output to include:

- status and stable group id
- method and resolved source route
- route pattern and pattern outcome when dynamic
- returned group directory or manifest
- exact case ids and every member input directory
- source revision and case-inventory identity
- persisted JSON report path

Treat missing commands, unmatched routes, ambiguous patterns,
overlapping case membership or same-method route specifications, missing cases, duplicate case ids, stale group inventory,
or a changed source revision as `blocked_grouping`. Do not replace the command
with an AI-authored target script or a hand-maintained case list.
`blocked_grouping` is a grouping diagnostic, not the operation handoff status;
return `action_required` with its exact cause, owner, acceptance check, and
resume point unless the main skill's separate recording-data blocker proof is
satisfied.

`traffic-e2e prepare` delegates to
`traffic-e2e diagnose case-group ensure`; direct low-level invocation is for
diagnostics, not the normal AI workflow. Dynamic groups and shared-directory static groups are manifest-backed:
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
final aggregate to cover the exact completion case set. A
`blocked_grouping` diagnostic ends that grouping attempt, leaves the parent
collection non-passing, and cannot be counted as a passed group.
