# Implementer evidence

`backend-rewrite evidence --api /route` reads the assigned API's current
failure evidence. Run it against the canonical Target root. It reads the saved
Replay attempt and leaves the workflow at its current step.

## Read the failure evidence

Start with `attempts` for the Replay attempt and Case counts, then read
`failures` for the grouped causes. Each group provides a representative with
the source of its observations. Read `expected` as the Source observation
and `received` as the Target observation when both can be identified.

Response clusters group the same difference type and path pattern. The default
shows a bounded selection of clusters with counts and one representative each.
Compound JSON values show their type and length. The representative Case and
assertion report contain the full difference.

- Response differences point to the status, header or body location. Use the
  presence state to distinguish a present JSON null, a missing field and an
  unavailable response.
- Dependency mismatches describe an observed Target call. Unconsumed Source
  dependencies describe expected calls still pending when the Case ended.
  A dependency failure can explain a later response difference in the same
  Case. Response differences in independently affected Cases remain visible.
- Runtime or Replay failures point to the failing phase and relevant diagnostic
  evidence.

Use an included original request or dependency to reproduce the representative
failure. `representative.case_dir` points to the recorded Case. Follow the
more specific artifact reference when the original payload is stored
separately. For a grouped route, keep each representative tied to its recorded
HTTP method. A failure can include `hints` with a comparison location and a
registered `rule_candidate`. An isolated value difference may carry an
`investigate_rule` hint. Confirm applicability from Source behavior before
proposing a rule to the coordinator.

For dependency failures, `representative.dependency_scope_path` identifies the
recorded Case scope. When present, `case_dependency_query` reads that scope
and resolves its recorded positions to the underlying dependency files.

## Deliver the fix

Use the assigned worktree and frozen base in `assignment`. Return the exact
committed fix and original assignment identities to the coordinator. Handoff
admission reads the API, dispatch, lease, handoff ID and commit.

Use `dependency-attribution show --api /route` for complete ownership and
hypothesis records when the investigation requires them. Rule planning uses
its own evidence and Source proof.

## Occurrence metadata reuse

The runner shows a generating-evidence phase while Replay finalizes. Finalized
reports carry the original occurrence UUID, capture owner and completeness for
unused Case MySQL and Redis traffic when available, including Redis Pub/Sub
notifications. The report binds the projection to the sealed Source manifest
and the actual Replay session. The finalizer projects these fields from loaded
Case data, and logs the projection time as `evidence_generation_ms`.

The API detail reader authenticates the sealed Source and uses the published
projection when it covers the selected unused rows. Older reports, missing
metadata and selections with unsupported unused protocols use the on-demand
cache. Its first lookup streams original dependencies into compact capture,
completeness, native-reference and HTTP-reference metadata for the selected
API's complete unused-reference set.
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

After Source authentication, published evidence and warm lookups skip the
original occurrence traversal. A cold fallback query can cost proportionally to
the recording size. No cache proves ownership, certifies a rule or substitutes
for complete Source/independent Target proof, native finite consumption or
genuine Replay.

## Measured query costs

The November 5, 2026 measurement used a sealed central ledger of 2,126,106,298
bytes and 847,979 physical records. The overview comparison retained the same
issue and attempt; all runs used optimized binaries.

| Query | Wall time | Public output |
| --- | --- | --- |
| Previous API overview | 52.74 s; earlier CPU sample covered 30.59 s | 41,990 bytes |
| Previous lightweight API overview, three runs | 0.0797–0.0812 s | 21,934 bytes |
| Full detail, first lookup of its unused-reference set | 43.72 s | 19,803 bytes |
| Full detail, repeated lookup of that set | 0.2905–0.2945 s | 19,803 bytes |

The detail measurement used the then-current 92 unused physical occurrences.
Its derived metadata was 94,068 bytes. Recording authentication and original
first-use traversal remain real work; a changed unused-reference set can require
a new cold lookup. The compact API result uses saved attempt evidence. These
historical measurements cover evidence queries.
