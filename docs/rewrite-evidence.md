# Implementer evidence queries

`backend-rewrite evidence --api /route` reads the assigned API's current issue
without running Replay or advancing the workflow. Overview schema 5 prioritizes
what differs, where the observation came from and which query can distinguish
the next hypothesis. The complete ownership inventory is loaded on demand.

## Read the overview

- `context` binds the canonical Target, workflow, recording and worker dispatch.
- `facts.issue` retains the current issue and representative expected/actual
  observations with explicit presence. A present JSON null is not missing.
- `facts.method_apis` and `facts.method_issues` retain every included method.
  Method `query_ids` refer to the single top-level `queries` command catalog.
- `facts.diagnosis.focus` prioritizes actual dependency rejection, unconsumed
  required calls, runtime interruption, response differences or code findings.
  A dependency rejection can explain downstream missing response events in that
  same Case; another Case retains its own cause.
- `facts.diagnosis.mismatches` groups at most six operation/kind/reason patterns
  from displayed execution failures. Each representative has a Case, original
  Target event index and JSON pointer into the original failure. Group counts
  cover only the overview rows. `execution_failures_summary` and its returned
  query retain complete Case pagination.
- `facts.diagnosis.next_queries` orders the relevant query IDs. Execute the
  matching `queries[].command` without reconstructing opaque IDs.
- `facts.diagnosis.strategies` separates Target code repairs, investigations and
  conditional policy candidates. Each candidate states a condition and the
  Source proof needed. A supported capability or observed difference never
  authorizes a rule. The detail evidence, coordinator plan/apply and fresh Replay
  retain their ordinary contracts.

For example, an observed Redis lane blocker points to its original Case and
`diagnostic.blocked_by`, then the dirty-cluster query. Investigate the required
predecessor, native session and Source construction before choosing a repair or
a supported native contract. A generated-value format alone cannot remove a
predecessor. An unrelated SQL rejection remains a separate mismatch group.

## Request complete details when relevant

`facts.api_information` contains `deferred: true`, a retained attempt summary
and the query ID for the complete dependency attribution projection. The retained
gates are historical observations; they do not establish current acceptance or
policy freshness. Execute that exact query when unused Source occurrences,
ownership claims, hypothesis attempts or verification obligations are relevant.
It returns the existing `target-api-information/v3` facts and their pagination.
`dependency-attribution show --api /route` remains available independently.

The overview does not read the entire central `dependencies.jsonl` to construct
that inventory. It also does not duplicate method command specifications. Missing
execution evidence is explicit rather than being treated as zero failures.
Detail reports retain their own schema and evidence identities. Overview IDs
remain diagnostic identities and cannot authorize policy planning.

## Occurrence metadata reuse

The first full occurrence query authenticates the sealed recording and streams
its original dependencies into compact capture, completeness, native-reference
and HTTP-reference metadata for the selected API's complete unused-reference set.
The cache identity includes the method, authenticated input membership and every
selected physical/native reference; another unused inventory cannot reuse a
narrower selection. Native ambiguity and notification identity checks remain
unchanged. An empty unused inventory needs no original dependency traversal.
The checksummed disposable cache lives in the
private dependency-index directory outside immutable recording evidence.

Every subsequent lookup authenticates the sealed membership and file identities
before using metadata bound to the manifest content identity and full central
file stamp. Same-size changes with a restored modification time still change
the native change time and cannot hide behind the cache. A corrupt envelope,
schema mismatch, changed manifest or another recording rebuilds or rejects as
appropriate. Policy-dependent Case defaults are recomputed separately; they are
never frozen into recording-only metadata.

Warm lookups avoid traversing business payloads. First-use full queries can
still cost proportionally to the recording size. No cache proves ownership,
certifies a rule or substitutes for complete Source/independent Target proof,
native finite consumption or genuine Replay.

## Measured query costs

The November 5, 2026 measurement used a sealed central ledger of 2,126,106,298
bytes and 847,979 physical records. The overview comparison retained the same
issue and attempt; all runs used optimized binaries.

| Query | Wall time | Public output |
| --- | --- | --- |
| Previous API overview | 52.74 s; earlier CPU sample covered 30.59 s | 41,990 bytes |
| Lightweight API overview, three runs | 0.0797–0.0812 s | 21,934 bytes |
| Full detail, first lookup of its unused-reference set | 43.72 s | 19,803 bytes |
| Full detail, repeated lookup of that set | 0.2905–0.2945 s | 19,803 bytes |

The detail measurement used the then-current 92 unused physical occurrences.
Its derived metadata was 94,068 bytes. Recording authentication and original
first-use traversal remain real work; a changed unused-reference set can require
a new cold lookup. The ordinary overview performs neither operation. These
measurements describe query latency, not Replay execution or verification speed.
