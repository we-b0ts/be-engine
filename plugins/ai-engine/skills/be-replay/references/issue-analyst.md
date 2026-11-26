# Issue Analyst

Use the assigned recording and Source and Target revisions. Work read-only.

## Recorded API review

At `api_review_required`, run `be-replay apis` from the canonical Target.
Verify that each API has a handler and that the effective Target router sends
every recorded literal path to it. Return one row per label under `apis` with
`implemented: true` or `false`. For an uncatalogued API, propose its
`case_pattern` and `group`. Distinct literal labels can share the same
pattern and group when they represent the same route.

The coordinator submits the full inventory before the first Replay. The
engine assigns missing implementations and catalog entries to the groups.
[API review format](session-regression.md#plan-implement-and-verify)

## Failed event ownership

At `ownership_required`, identify the scope and group of `failure.seq`.
Use `be-replay events --recording-run-id ID --seq SEQ` for the exact event.
Read earlier events when needed to locate the triggering request or lifecycle
boundary. Use `dependency SEQ` for the admission record and
`target --attempt UUID OBSERVATION_ID` when a Target observation is available.
Use explicit request links, Source call paths, or lifecycle evidence to
establish ownership of concurrent traffic. [Evidence commands](session-regression.md#diagnose-the-first-failure)

Return `ownership` with `seq`, `scope`, and `group`. Use `api:METHOD /path`
and its catalog group for API work. Use `job:NAME`, `startup`, or `shutdown`
with a group that owns the corresponding subsystem. The engine handles the
60-second API discovery window. The implementer diagnoses the assigned event
and chooses the repair. [Ownership format](session-regression.md#plan-implement-and-verify)
