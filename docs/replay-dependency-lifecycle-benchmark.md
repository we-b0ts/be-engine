# Dependency lifecycle Replay benchmark

This benchmark compares the original engine at
`1bd161d5034208228e1c3ca4dd00353cb420df41` with the dependency lifecycle rewrite.
Both binaries use the repository's default release profile, the same Cargo.lock,
Rust 1.99.1, and the same Intel Xeon Gold 6240R host (32 logical CPUs). Builds,
Clippy and tests finish before timing begins.

The paired inputs contain identical logical requests, responses, Case UUIDs and
protocol identities. The baseline reads its original layout; the candidate reads
the current sealed central ledger and scope views. The fixture adapter accepts
only explicitly marked synthetic benchmark inputs. It is not a production
recording migration path.

## Measurements

Each workload runs once without persistent engine indexes, then three times with
those indexes available. Reuse results are medians. The first sample is a first
persistent-cache build, **not a disk-cold measurement**: fixture generation and
input hashing have already populated the operating system's page cache. Each
sample launches a new process. Wall time includes startup, Cases and finalization;
CPU and peak RSS cover that process. Request latency includes loopback transport.
Startup discovery polls at 20 ms intervals; this granularity can dominate the
smallest warm-inventory wall-time samples. CPU measurements do not include that
polling wait.

| Workload | Actual work |
| --- | --- |
| SQL | Five Cases, 80 reversed long SELECT requests per Case, 90 projection names, 19 unrelated value rules, and one deliberate unmatched request per Case. Responses are fixed synthetic OK packets. |
| HTTP hypothesis | Five Cases, 80 HTTP requests per Case with different generated UUIDs. All 400 requests need diagnostic pre-match evidence; the resulting hypotheses still require proof. |
| Pub/sub inventory | Load and report one subscription plus 8,192 notifications. No notification consumption is attempted. |
| Process inventory | Load and report 16,384 Redis GET occurrences. No request consumption is attempted. |

SQL validates 400 matches and five deliberate mismatches. HTTP validates 400
diagnostic deliveries. The inventory workloads intentionally retain unused
obligations. These samples measure engine costs; they are not successful complete
application migrations or database result-set throughput measurements.

Logical decision digests, response/error outcomes and inventory counts must agree
between binaries. Source input hashes must remain unchanged. Candidate Target
witness coverage must be complete without omissions. None of these checks permits
converting a hypothesis into a formal rule or an unused request into consumption.

Evidence bytes include all output files and the complete shared-artifact closure
referenced by the report, including reused artifacts. New shared writes and
derived index-cache writes are recorded separately; cache files are not counted
as evidence. A small report pointing to a large shared file cannot appear as an
evidence-size improvement.

## Results

The final comparison contains 32 samples. All four logical decision digests agree
across both binaries and all repetitions. Immutable inputs remain unchanged. All
candidate witness manifests are complete with zero omitted observations; all 400
HTTP hypothesis attempts and selections are retained.

Persistent-cache reuse medians (each cell is **baseline → candidate**):

| Workload | Wall ms | CPU ms | Peak RSS MiB | Total evidence MiB |
| --- | ---: | ---: | ---: | ---: |
| SQL | 3,868.0 → 3,990.0 | 3,818.9 → 3,928.8 | 55.86 → 58.78 | 4.202 → 4.253 |
| HTTP hypothesis | 407.0 → 1,039.8 | 355.4 → 498.0 | 49.95 → 64.37 | 3.164 → 5.118 |
| Pub/sub inventory | 27.36 → 28.14 | 16.61 → 22.86 | 27.75 → 30.52 | 1.341 → 1.347 |
| Process inventory | 641.8 → 643.1 | 656.5 → 652.4 | 49.00 → 57.52 | 4.046 → 4.067 |

First persistent-cache build, without a preceding engine index:

| Workload | Wall ms | CPU ms | Peak RSS MiB | New index-cache MiB |
| --- | ---: | ---: | ---: | ---: |
| SQL | 3,945.1 → 4,077.5 | 3,864.8 → 4,006.7 | 55.26 → 60.56 | 1.558 → 1.770 |
| HTTP hypothesis | 423.8 → 1,109.9 | 360.8 → 525.1 | 50.04 → 64.52 | 0.270 → 0.478 |
| Pub/sub inventory | 190.8 → 699.3 | 132.7 → 581.4 | 29.50 → 35.79 | 1.312 → 2.634 |
| Process inventory | 1,826.0 → 2,525.5 | 1,443.8 → 1,950.3 | 50.61 → 58.22 | 12.199 → 20.140 |

Request latency medians across the three reuse runs, in milliseconds:

| Workload | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| SQL | 9.108 → 9.291 | 16.851 → 17.199 | 17.666 → 18.025 |
| HTTP hypothesis | 0.652 → 2.085 | 0.721 → 2.543 | 0.895 → 2.874 |

The strict SQL workload adds 3.2% wall time and 2.9% CPU. This is a measured
regression, not a claimed speedup: reuse wall ranges are 3,866.7–3,869.1 ms for
the baseline and 3,988.4–4,002.4 ms for the candidate. Process inventory reuse
is effectively unchanged in wall time, while pub/sub inventory adds 0.78 ms wall
and 6.26 ms CPU. Complete ownership metadata and closure verification add first
build work; the larger inventory first samples remain slower than the baseline.

The hypothesis workload costs 2.55 times the baseline wall time, 40.1% more CPU
and 61.8% more evidence bytes. Its additional guarantees include retaining
rejected and selected guesses, independent protected Target observations and
durable authenticated checkpoints before diagnostic response delivery. The
comparison does not establish how many future application reruns those hints
save. Reducing reruns and reducing the cost of one Replay are separate outcomes.

The first profiling pass of this rewrite exposed a redundant full-ledger index
and JSON-tree copies. Removing them reduced the process inventory first-run peak
from 471.2 MiB to 58.2 MiB and wall time from 4,866.4 ms to 2,525.5 ms. That is an
improvement within the rewrite; the baseline comparison remains the tables above.

Exact measured binaries:

- Baseline SHA-256: `e78f1f91783661ef74f7893bc4b7ae3fced2586d8e0065f9596b582e330b8515`.
- Candidate SHA-256: `fe6297354d982403995d76354eafa342fb69a7cfadfe2d4992fa0231092b16cf`.

The candidate is an uncommitted working tree. Its displayed Git revision is
`1bd161d50342-dirty`; that revision alone does not identify its implementation.
Use the binary checksum and the source snapshot when reproducing the comparison.
The delivery source snapshot digest is
`5c09aa3011ed50facf9d40e152183aeced315ee462ba2e04c566264fc98c1bf2`:
SHA-256 over sorted relative paths, a NUL separator and each file's binary SHA-256
digest, covering `src/**`, `Cargo.toml`, `Cargo.lock` and `build.rs` (1,831 files).
Raw samples and retained synthetic artifacts for this run are in
`/data0/icy/.codex/tmp/dependency-lifecycle-performance/final-paired-v6-optimized/`.

## Performance changes

The implementation keeps original record offsets and checksums in frozen Source
references, so request evidence reads avoid reparsing an ownership scope. Lazy
Case loading reads only selected physical rows and uses their aggregate byte
count for prefetch. The payload LRU uses amortized queue compaction.

Mandatory Source closure streams the central ledger once and retains only compact
coverage state, rather than materializing another full payload-selector index.
Typed index envelopes hash their serialized payload directly and deserialize
without constructing and cloning a second JSON tree. Selectors copy retained
fields without first copying response bodies that will be discarded.

Hypothesis persistence uses one Tokio blocking filesystem transaction per bounded
batch. Every affected protected payload is still synchronized before the journal
acknowledgement. Directory entries are synchronized when a new payload segment is
published; later appends synchronize its data. Missing payloads, failed writes or
an incomplete journal prevent diagnostic delivery acknowledgement.

## Reproduction

Build the original commit in an isolated checkout and copy its release binary to
`/tmp/traffic-e2e-baseline`; build the candidate with the same compiler. Use an
empty benchmark directory and stop other builds and tests before running:

```sh
cargo build --release --bin traffic-e2e
PYTHONDONTWRITEBYTECODE=1 python3 scripts/bench-replay-performance.py \
  --baseline /tmp/traffic-e2e-baseline \
  --candidate target/release/traffic-e2e \
  --work-dir /tmp/dependency-lifecycle-comparison \
  --cases 5 --queries 80 --notifications 8192 --global-exchanges 16384 \
  --workloads sql http-hypothesis pubsub global --repeats 3 --keep-artifacts
```

The script saves exact binary SHA-256 values, versions, immutable input hashes and
individual samples in `benchmark-results.json`. Managed-default lazy Case loading
is enabled for both binaries. No target application, DNS rewrite or interception
rule is started. The synthetic encryption key and all runtime artifacts stay in
the selected private benchmark directory.
