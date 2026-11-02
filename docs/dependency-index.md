# Dependency index and Replay preparation

Managed `run` / `run-api` prepare dependency indexes before building the target
image and starting Replay. The index preparation deadline defaults to 1800s;
Replay listener readiness retains its separate 60s deadline. Progress reports
identify index preparation, image build, Replay preparation, target startup,
execution, and finalization. Per-case dependency preparation is included in replay
execution progress. An old recording needs one complete read to build its indexes;
subsequent runs validate and reuse them.

```yaml
project:
  replay:
    startup_timeout_seconds: 60
    dependency_loading:
      lazy_cases: true
      cache_bytes: 268435456
      index_timeout_seconds: 1800
      case_timeout_seconds: 180
```

These defaults apply to managed Replay without editing existing version-18 project
configuration. A byte budget of zero disables the immutable record cache.
The cache is capped at 4 GiB. A case preparation failure returns from `begin`
before the primary request is sent and remains an incomplete case.

## Index lifecycle

Recorder creates `.dependency-index.json` together with the case dependency
summary, before publishing the case. Both consume the same read and JSON parse.
At run finalization it creates `.global-replay-index.json` and portable Global
metadata/notification pages while computing the Global summary. These indexes
travel with the completed recording, so first use on another host can validate
and reuse them instead of scanning the original payload again.
Recorder refreshes the sealed fragment identity after its own final ownership
assignment, checking unchanged size, inode and modification time without reading
the payload again. Ordinary Replay never relaxes change-time validation.
Old recordings remain immutable: missing or stale fragments are built under
`.traffic-e2e/local/dependency-index/`. Evidence outside a managed project uses a
per-user temporary cache instead. Run manifests aggregate fragment metadata and
validate the complete published file set and run identity. Index format version,
file size, device/inode, nanosecond modification/change times, and checksums detect
staleness and corruption. A changed file or added/removed case invalidates the run
manifest. Readers check source identity on every read/cache hit and verify the
SHA-256 of each indexed byte range. Indexes are locators, never matching or
sharing authorization.

Attribution freezes reference views only for memberships that change. Unchanged
Startup, Process and Case scopes keep their original immutable paths and file
stamps, so assigning a late unowned Case dependency does not invalidate unrelated
native indexes. A moved member rebuilds both its previous and effective scopes;
the complete attribution snapshot still binds every Replay.

The index includes exact HTTP endpoint/method/path hashes, exact Redis command
argument hashes, original line numbers and byte ranges, endpoint/connection
metadata, and complete Redis lane counts. Duplicate exchanges retain distinct
locations. Response bodies and MySQL result rows are absent. Failed/truncated
candidate records remain subject to the original protocol eligibility checks;
Redis sharing still rejects a selected fragment of a larger source lane.
Connection metadata and diagnostic errors can be sensitive: cache directories use
mode 0700 and index files use 0600. They must not be committed or shared publicly.
Writers use cancellable process locks and atomic, flushed file replacement. An
interrupted build cannot publish a partial run manifest; completed file fragments
remain reusable.

## Loading and caching

HTTP and Redis cross-case loaders and HTTP evidence planners read located records
instead of scanning unrelated dependency bodies. Global dependencies, connection
metadata, advertised/fake-IP endpoints, TCP blackholes, selected Redis exchanges,
and explicit cross-case evidence are available before target startup. Selected
Redis data stays eager because snapshot overlays, lock/time-shift rules and lane
classification need complete evidence.

Ordinary HTTP, MySQL, Memcached, Kafka and Motan case exchanges are prepared at
`begin`. MySQL optional-session classification sees the complete original case
sequence. Case identities and endpoint allocation remain available at startup.
Dynamic source-value observation moves to case preparation. An implicit
single-directory Replay prepares its initial active case before serving traffic.
Motan debug heartbeat templates retain startup loading.

Disk indexes survive sessions. The in-memory LRU retains only immutable source
bytes, up to the configured budget; oversized case files are read without being
cached. Managed Replay queues one bounded read ahead for the next case. The runtime
supervises this immutable prefetch; it never installs exchanges or changes case
status. Preparation still checks the source and parses the complete case.
Parsed active evidence and response buffers owned by a driver are separate
from this cache budget. Consumption counters, connection claims, dynamic bindings,
and rule state stay in their Replay session. Repeating `begin` does not reload an
already prepared case. Ended cases in lazy mode require a fresh Replay session.
Consumed case MySQL rows and HTTP/Memcached/Motan/Kafka response payloads are
released after case completion while preserving positions, statuses and reports.
Global/reusable, unused and in-flight evidence stays available. This is not a total
process RSS limit: a single large active case and required startup evidence still
need memory.

Low-level Replay preserves eager loading by default. Opt in with
`replay --lazy-case-dependencies --dependency-cache-bytes 268435456
--case-prepare-timeout-seconds 180 CASE_DIR`, or the launcher configuration's
`replay.dependency_loading` mapping. Prepare/validate an existing recording with:

```bash
traffic-e2e diagnose dependency-index --case-source /path/to/completed/run
```

The command reports `built`/`reused`, file count, source bytes and index location.
It never starts a target or changes recording evidence.
Preparation byte counts describe the selected Case or Global scope. Several
scopes can refer to one central ledger; its full file stamp still authenticates
their original locations and is not counted again for each scope.

## Shared Global evidence

Global report inventories are durable derived evidence under
`.traffic-e2e/local/artifacts/shared-global-inventories/`, separately from the
disposable dependency-index cache. Source identity, projection version and the
relevant policy/layout identity select an immutable inventory. Each Replay keeps
its own visibility or notification-delivery changes and exact counts. Unused
details are projected from the shared inventory only when requested; finalization
and publication normally reuse it across APIs. A cross-case rule that reclassifies
native Global HTTP entries changes their runtime metadata/order; those sessions
retain the original full HTTP projection rather than reuse an incompatible one.
Native protocol matching, finite consumption and Case ownership remain unchanged.
Recorder also prepares these report projections for its already admitted policy
at run finalization, using the same Source-only protocol adapters as Replay. The
portable inventories live under the recording's `.replay/` directory and
`.global-report-preparation.json` records their source/policy/version identity and
preparation status. They contain no actual Target observation. A first Replay
imports matching inventories once into its shared artifact owner; later APIs
reuse them without visiting all Global rows. A different Source or policy gets a
different identity. Changed rules and older recordings retain on-demand rebuilds.
Prewarm failure is explicit and preserves recording completion semantics and
original bytes; it does not authorize Replay to bypass its native validation.
The report-preparation marker does not certify that every native scoped-view
index is portable. Native Process indexes built in the Recorder's local cache
can still require an initial rebuild after copying a recording to another root
or host. Report inventories and native scope indexes have separate identities;
neither can substitute for a different membership view. The listener readiness
budget must cover any native preparation that remains before it starts serving.
An unreferenced prewarm may be rebuilt from intact Source; missing or changed
evidence already referenced by a published report remains an error.
See [Replay performance](replay-performance.md) for the implementation boundaries
and a reproducible, isolated before/after benchmark.

## Local acceptance measurement

On the completed `20261008073501` recording, an unoptimized debug build indexed
5,622 published dependency files (9,005,913,861 bytes). The first build took
600.34s; reuse validation took 1.87s. These source bytes exclude failed/staging
cases and the separately loaded Global file. A local Replay of the 147
`GET /api/models/unified` cases with the existing policy and recorder configuration,
loopback listeners and interception disabled became ready in 6.22s. Its HTTP
cross-case preload read 4,302 candidate bytes. No target container or primary API
request was started for this measurement; it validates the startup bottleneck,
not the target's complete business replay result. Times depend on CPU, disk and
filesystem cache state; the first build used the earlier development build before
a redundant hash of unrelated record ranges was removed.
