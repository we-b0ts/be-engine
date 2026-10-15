# Large Global dependency recordings

Task: `vjqkM8lTQi` — 长时录制Global依赖全协议性能优化.

Global evidence uses the same immutable source-record reader and byte cache as
Case evidence. MySQL, Redis (ordinary commands and RESP2 Pub/Sub), Memcached,
HTTP/HTTPS, Kafka and Motan retain their protocol matching, finite consumption,
ordering and existing explicit reuse policies. An index supplies locations and
metadata; it never grants sharing or supplies replacement responses.

## Recording completion and index preparation

After dependency writers are flushed, Recorder streams the Global JSONL once
to build its summary and `.global-replay-index.json`. The index references
checksum-protected pages under `.global-replay-pages/` using relative paths.
These files are sealed before the completed recording is published. Ownership
assignment refreshes the source's ctime only if its size, inode and mtime remain
unchanged. Case fragments retain the existing `.dependency-index.json` format.
Pre-readiness statistics also traverse the source with bounded line buffers.

For older recordings, the first preparation builds the Global index outside
the immutable recording, under the project's private local dependency-index
cache. Builds use a file lock, atomic checksummed manifests, progress events and
the existing cancellable index preparation deadline. Later preparations reuse
the source identity and version. A changed source causes reconstruction; each
materialized original record is additionally checked against its byte range and
SHA-256. Corrupt pages fail explicitly rather than becoming an empty inventory.
Copying a recording to a different filesystem changes its identity and can
require reconstruction. Moving a sealed tree preserves its relative page links.

Managed E2E prepares Case and Global indexes in the `preparing_index` phase,
before building Target and starting Replay readiness. For direct inspection:

```bash
traffic-e2e diagnose dependency-index --case-source /absolute/completed/run
```

The report's `files` and `source_bytes` describe Case files;
`global_source_bytes` describes the additional Global source. `status` describes
the Case run manifest; a reused Case manifest may accompany a newly built Global
index. Progress events identify Global construction separately.

## Replay memory and scheduling

The disk index stores request and response metadata, while large Global response
bodies, MySQL rows and Kafka values remain in their original JSONL records.
Replay loads response payloads when selected. Kafka produce comparisons read the
original key, headers and value before admitting a match. MySQL retains original
row counts and row-width validity for session and projection proofs.

The configured `replay.dependency_loading.cache_bytes` budget covers cached
original record bytes across both scopes. Its default is 256 MiB. Oversized
individual records can be read without being cached. Request metadata,
protocol state and in-flight decoded responses have separate lifetimes; this
budget is not a bound on total process RSS. Ordinary protocol request inventories
still grow with their record count, and their matching algorithms remain intact.

Uncorrelated Redis notifications use per-subscription position pages and compact
per-Replay consumption statuses. They no longer populate one resident payload
object or one Tokio task per notification. One ordered scheduler per confirmed
subscription reads metadata pages, waits for the recorded absolute deadline,
then materializes the next payload. Unsubscribe and disconnect cancel its wait.
The former 65,536-message inventory ceiling is removed; existing framing,
subscription and unsafe-evidence checks remain. Recorder's Redis output queue
also applies backpressure with 256 slots. Its response-order buffers retain their
existing behavior.

Global debug-file traversal is streamed. Explicit Redis snapshot proof uses the
Global metadata index and reads only matching original responses; its existing
exchange and byte limits are enforced during collection.

## Counts and complete details

Main reports retain up to 100 unused Global samples per protocol and exact
counts (`unused_global_exchange_count`, `unused_global_http_exchange_count`,
or a protocol's `unused_global_count`). Older reports without the counters still
use their complete arrays. Case dirty checks and ownership do not change.

Finalized reports reference complete unused Global detail pages beside the
report. Runner publication copies these pages into the published snapshot.
Background reclassification adjusts exact counts and supplies its reversible
Case-to-Global witnesses after the immutable native detail pages.

```bash
traffic-e2e diagnose global-dependencies \
  --report /absolute/replay-report.json --protocol redis --offset 0 --limit 100
```

Supported protocol names are `mysql`, `redis`, `memcached`, `http`, `kafka` and
`motan`; limits are 1–1000. `next_offset` identifies another page. Redis Global
push detail indexes refer to zero-based source JSONL lines; connection and
subscription sequence remain part of each witness.

Index-preparation and Replay-startup failures retain their stage and bounded
Replay stderr in diagnostics, including failures before any API request executes.

## Measurement

On the development host, the completed recording `20261015093242` contains
3,105,338,735 Global source bytes (2.89 GiB), including 1,422,547 notifications,
and 3,856 Case files containing another 2,623,580,642 dependency bytes.
Release-mode `diagnose dependency-index` measured:

| Preparation | Wall time | Peak RSS |
| --- | ---: | ---: |
| First Global construction, existing Case index reused | 63.10 s | 125.52 MiB |
| Global and Case index reuse | 0.29 s | 115.91 MiB |

These measurements cover index preparation on this host, including Case
manifest validation. They do not establish API correctness or an RSS guarantee
for replaying arbitrary request inventories. Missing original subscription
anchors remain startup errors and identify their connection, sequence and target;
indexing cannot reconstruct absent evidence.

A warm, selected-first-API Replay preflight reached subscription validation in
0.28 s with 31.99 MiB peak RSS. It failed explicitly on connection
`95478b48-94f0-4357-9809-6d8be4475fe1`, subscription sequence 4, whose recorded
SUBSCRIBE belongs to another Case outside that selection. This is a failed
preflight measurement, not a passing API run. The original recording remains
unchanged. New Recorder finalization takes effect when deployments use the
updated engine; existing container images do not acquire local binary changes.
