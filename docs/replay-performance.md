# Incremental Replay evidence and performance

Task: `KCYgNKF0ZW`. Baseline executable: `e12844d2bedb`.

Replay records results, rule usage, original identities and evidence references
as session increments. A routine successful case should add KB-scale result and
index metadata. Necessary unique request/response payloads have their own explicit
storage budget; they are not silently truncated to meet a metadata size target.

## Boundaries

- SQL templates are prepared once per policy. Cheap selectors reject unrelated
  statements; a bounded cache shares only immutable raw tokens. Parameters,
  scopes, Source physical-table identity, bindings and clocks remain live checks.
- Codec plans reuse immutable Protobuf bindings. Source delivery validation uses
  its already decoded value. Unknown wire fields and unselected encoded bytes
  retain their original strict comparison behavior.
- Protected evidence separates Source observations, actual Target requests,
  derived deliveries and candidate associations. Every physical Target request
  receives its own identity, including unmatched requests. Equal content shares
  encrypted storage; it does not share request identity, timestamps or consumption.
  Associations and metadata are authenticated. Offline discovery and plan
  preflight reconstruct pairs through the same reader.
- Global report projections are shared durable inventories, identified by the
  immutable Source, projection version and applicable policy/layout identity.
  Each session owns its sparse visibility changes. Protocol owners retain their
  existing definitions of unused: MySQL optional sessions, Redis reusable
  snapshots, Kafka sections and Pub/Sub delivery are not interchangeable states.
- Global Pub/Sub notifications already have process ownership and no Case unused
  obligation. Reports preserve confirmed subscription provenance, exact counts,
  actual delivery changes and the original inventory reference. Case commands and
  correlated RPC callbacks keep their matching and consumption obligations.
- Detail queries read only required pages. Shared inventories are outside the
  disposable index cache. Publication reuses them within a project and explicitly
  stages/rebinds them for exports. Missing or modified evidence is an error.
- Final classification and aggregation borrow one loaded report. Classification
  remains reversible, and full session/sibling coverage and path checks remain.

Incomplete retention is explicitly reported and cannot authorize a rule plan.
Evidence storage limits must not independently change native protocol matching
results for traffic already supported by that protocol.

`policy_witnesses.complete` covers the Case observations admitted to unified
rule evidence and their candidate relationships. It also covers genuine admitted
Target requests with no candidates. It does not mean every Source exchange was
consumed, every Case was activated, every Target matched, or E2E passed. Native
protocol reports retain rejected framing/Host requests, Global traffic and
RPC/PubSub ownership; those observations do not acquire ordinary Case-rule
authority merely by sharing storage. Rule preflight separately validates its
complete immutable Source scope.

Global loading preserves two registration phases so subscription/RPC anchors
precede linked exchanges. Each phase decodes only its relevant record types and
passes bounded page batches, preserving Source order and the final Source stamp
check even when a phase selects no records. This avoids a cross-thread wakeup
for every background record.

Recorder prepares the immutable locators while writing Case and Global summaries.
At finalization it also prewarms portable report inventories for its already
admitted rule policy. Replay uses the same Source-only projection owner, imports
a matching Source/policy/layout/version once, then reuses its project inventory.
New policies and older recordings use the same cold fallback. No Target request,
comparison outcome, dynamic binding or independent Target proof can be precomputed
from Source alone. Optional prewarm failures retain their explicit status without
changing recording completion or weakening later Replay validation.

One dynamic HTTP layout remains on the original report path: a cross-case rule
that also reclassifies a native Global HTTP exchange changes shared-origin
metadata and capture-time ordering. That session skips HTTP shared projection
reuse and generates its full native HTTP details. Other protocols and ordinary
HTTP Global traffic continue to share inventories. Preserving this exception
avoids changing native candidate order for a storage optimization; optimizing it
requires a separate stable Source-identity to runtime-index projection.

## Reproducible measurement

The benchmark runs two real Replay executables on the same generated immutable
fixtures. It uses loopback listeners and `--no-intercept`; it starts no project
target, changes no DNS or iptables state, and advances no rewrite workflow.

```bash
python3 scripts/bench-replay-performance.py \
  --baseline /path/to/baseline/traffic-e2e \
  --candidate /path/to/candidate/traffic-e2e \
  --work-dir /path/to/private/benchmark \
  --cases 3 --queries 54 --notifications 1577726 --repeats 3
```

Running first with only `--baseline` saves the input identities and samples;
adding `--candidate` later reuses those exact inputs. Each binary has one warmup
and three measured sessions per workload. The script compares protocol decisions
and selected SQL identities, verifies the source files did not change, and records
startup, case, finalization, child CPU and generated artifact sizes. Transient
per-session output is removed after measurement unless `--keep-artifacts` is set.
Warmup means the first session of that binary and derived-cache preparation;
it does not clear OS page caches. The baseline runs first, so the candidate reuses
its Source indexes while preparing its new shared projection. Subsequent sessions
measure reuse. Original recording index creation, when needed, is included in the
baseline's first startup rather than measured as a separate phase. Artifact sizes
sum logical file lengths; they do not measure filesystem allocation or discount
hard links. Shared inventory growth is recorded separately from session output.

The SQL workload sends 54 wide SELECTs per case, in reverse selection order,
under 19 unrelated global write-time rules, followed by a genuine unmatched
query. The Pub/Sub workload has one confirmed Global subscription and 1,577,726
unconsumed notifications; the case has no dependency calls. These fixtures isolate
engine costs. They are not an E2E acceptance result for a rewritten service.

The ordinary Global workload isolates process traffic without Pub/Sub: 131,073
finite Redis GET exchanges, with no Case calls. Run it in a separate directory:

```bash
python3 scripts/bench-replay-performance.py \
  --baseline /path/to/baseline/traffic-e2e \
  --candidate /path/to/candidate/traffic-e2e \
  --work-dir /path/to/private/global-benchmark \
  --workloads global --global-exchanges 131073 --repeats 3
```

Local component measurements can also be run with the ignored tests
`delivery_preparation_benchmark` and `protobuf_schema_preparation_benchmark`.
Their timings isolate decoded-value/schema reuse rather than whole-version speed.

## Measured results, 2026-10-17

Same host, release binaries, one warmup followed by three measured sessions per
binary/workload. Medians below compare baseline `e12844d2bedb` with optimized
`c1df5749ae81-dirty`; only benchmark/documentation files were uncommitted in that
optimized build. Inputs, encryption-key identity, matching decisions, exact
Source candidate indexes, SQL/parameters, genuine mismatches and counters were
verified across both versions. All SQL sessions retained complete policy evidence
with zero omissions.

| Workload | Whole Replay, before → after | Child CPU, before → after | Per-session artifacts, before → after |
| --- | --- | --- | --- |
| SQL: 3 cases, 162 matches, 3 genuine mismatches | 17.021 s → 0.533 s (31.9×) | 12.603 s → 0.503 s | 58.24 MiB → 2.43 MiB |
| Pub/Sub: 1,577,726 unconsumed notifications | 27.425 s → 0.0296 s (926×) | 16.655 s → 0.0183 s | 300.44 MiB → 27.35 KiB |
| Ordinary Global: 131,073 Redis GETs, no Case calls | 9.430 s → 5.131 s (1.84×) | 8.815 s → 5.220 s | 24.36 MiB → 26.25 KiB |

The SQL total includes necessary unique protected payloads and the observation
graph for all three cases. It is not merely status metadata. Pub/Sub creates
262.95 MiB of shared logical inventory once; later sessions add zero shared
bytes. Ordinary Global creates 32.45 MiB once, also with zero shared growth in
later sessions. The existing-recording fixtures do not contain Recorder prewarm
artifacts: the candidate's first session includes their cold construction
(Pub/Sub 0.131 s; ordinary Global 7.510 s). Separate tests verify new recordings
prewarm and import the same Source/policy/layout identities without revisiting
native rows.

The ordinary Global workload still needs about 5.000 s of native matching
inventory startup, versus 7.309 s before. Finalization falls from 2.080 s to
0.181 s. This change removes repeated large report writes while preserving the
existing eager native matching model; it does not claim constant-time startup
for arbitrary Global protocol traffic. Native recorded delays and business
timeouts are outside these isolated synthetic workloads.

## Acceptance

- Preserve matching precedence, finite consumption, native request validation,
  strict unselected values, independent clocks and Source/Target/delivery roles.
- Preserve complete, tamper-evident observation coverage and rule plan/apply
  eligibility; verify unmatched and repeated physical requests independently.
- Compare lazy details against the previous full visitor, including ordering,
  pagination, optional-session failures, reusable snapshots and reversible Case
  overlays. Two sessions must retain independent visibility state.
- Where the shared layout applies, a second API with no Global consumption
  generates only its result and references, without rewriting or copying the
  entire shared Global inventory.
- Run repository format, test, strict Clippy and code-organization checks before MR.
