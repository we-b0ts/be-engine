# Per-Case protocol execution performance

Task: `1032990_1#105761` (`3mAYhJylTs`). Measured on 2026-10-31.

The 128-Case workload reduces Redis Case p50 by 18.8–21.8% without prefetch
and 17.1–21.7% with in-Case prefetch. MySQL p50 increases by
about 0.18–0.24 ms per Case in the main 128-Case comparison. Its indexes
already partitioned candidates before this change. These data do not establish
which individual new ownership/preparation operation accounts for that cost.
The implementation retains the shared ownership, cancellation and evidence
checks rather than removing them to improve the metric.

## Fixed revisions and conditions

| Binary | Revision | Binary SHA-256 |
| --- | --- | --- |
| Baseline | `0609b37e5eb56ec200cce868ac01df5a1fc0e1d0` | `bbf0ded3ff7baffb811282fa4d3bf4919ff0898a78e34d1090b73d3702cd8514` |
| Candidate | `87ca5e37aba216b872e748611d10a84bc3114b62` | `0ba3263f870807b132a17bbc206f0d18581c44fc19080ee34f9c7bc32e034ffa` |

Both binaries use Release builds on the same Linux host. Their version metadata
reports the same pinned Target runtime, while the measured Target is a host
Python HTTPServer process; the runtime image is not used. The baseline was built from an isolated checkout before
its binary was copied. Both binary hashes are checked before and after samples;
no builds or repository tests ran during measurement.

Each pair receives byte-identical sealed synthetic central recording inputs,
policy and managed key, with separate persistent index directories. The fixture
and immutable input hashes are rechecked throughout. Sample order alternates by
repeat. No DNS interception, external dependency service or Docker startup is
part of the experiment.

Every Case executes 16 real Redis/MySQL wire requests inside an actual HTTP
Target handler. The Target program receives operation inputs, never recorded
response oracles. The driver independently asserts exact HTTP status,
content-type and body. The timer includes oracle preparation, optional prefetch,
Case begin/lazy dependency preparation, `request_begin`, real HTTP execution,
assertions and acknowledged Case end. Final batch publication and process
startup/shutdown are recorded separately, as are Replay/Target CPU and peak RSS.

The driver uses low-level Replay control with an independent Python HTTP client;
it does not measure the complete managed `run-api` driver/response-assertion
adapter path. Native primary adapters and their assertions are covered by the
repository tests. This is a synthetic serial-request workload, not a production
throughput or concurrent-dependency benchmark. PB, Motan, Memcached and pre-match
performance are outside this measurement; their supported correctness paths
retain separate tests.

## Main comparison: lazy loading, no prefetch

Each group has one empty-persistent-index warmup and three measured sessions per
binary. Tables aggregate measured Case times in sessions with persistent index
reuse; in-memory caches start fresh with each Replay process. OS page-cache
state is uncontrolled and fixture generation/hash reads may warm it. Each
128-Case group has three independent measured sessions, not 384 independent
experimental repetitions. Negative changes mean faster execution.

| Workload | Cases/session | Baseline p50 / p95 ms | Candidate p50 / p95 ms | p50 change |
| --- | ---: | ---: | ---: | ---: |
| mysql-strict | 1 | 6.590 / 6.621 | 6.801 / 6.880 | +3.2% |
| mysql-json | 1 | 9.273 / 9.383 | 9.658 / 10.813 | +4.2% |
| redis-strict | 1 | 5.675 / 5.923 | 5.912 / 5.982 | +4.2% |
| redis-json | 1 | 7.997 / 8.232 | 8.318 / 8.373 | +4.0% |
| mysql-strict | 16 | 5.551 / 6.788 | 5.677 / 6.490 | +2.3% |
| mysql-json | 16 | 7.943 / 9.011 | 7.941 / 9.004 | -0.0% |
| redis-strict | 16 | 4.785 / 5.684 | 4.798 / 5.869 | +0.3% |
| redis-json | 16 | 6.978 / 7.819 | 6.902 / 7.898 | -1.1% |
| mysql-strict | 128 | 5.818 / 6.053 | 5.998 / 6.215 | +3.1% |
| mysql-json | 128 | 8.069 / 8.314 | 8.313 / 8.654 | +3.0% |
| redis-strict | 128 | 6.419 / 6.968 | 5.020 / 5.169 | -21.8% |
| redis-json | 128 | 8.790 / 9.202 | 7.139 / 7.366 | -18.8% |

Phase times below are p50 and resource figures are medians of complete sessions.
The dependency timer is a subset of the HTTP request timer. CPU includes startup
and finalization; `/usr/bin/time` has 10 ms CPU resolution. RSS is peak process
memory, not retained per-Case memory.

| Workload, 128 Cases | Prepare p50 ms | Dependency p50 ms | End p50 ms | Replay CPU ms/session | Replay peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| mysql-strict | 2.830 → 2.929 | 2.287 → 2.360 | 0.188 → 0.188 | 880 → 900 | 103.50 → 105.00 |
| mysql-json | 3.385 → 3.514 | 3.972 → 4.072 | 0.188 → 0.193 | 1150 → 1190 | 107.25 → 108.50 |
| redis-strict | 2.224 → 2.279 | 3.575 → 2.113 | 0.120 → 0.121 | 1000 → 830 | 95.50 → 97.50 |
| redis-json | 2.269 → 2.327 | 5.842 → 4.173 | 0.126 → 0.126 | 1260 → 1060 | 87.75 → 89.50 |

Redis gains are concentrated in dependency matching, consistent with replacing
whole-inventory traversal with scope/operation postings and physical lane
membership. MySQL's preparation and dependency stages are slightly slower;
Case end is essentially unchanged. Whole-session CPU and RSS are reported so
that this cost remains visible.

## Single-Case confirmation: fifteen measured sessions per binary

A fresh paired experiment increases the small-batch repetition count. It
observes median increases of 1.7–2.9%; variation between runs remains and the
data do not isolate an individual overhead source. Tail latency remains more
variable than the medians.

| Workload | Cases/session | Baseline p50 / p95 ms | Candidate p50 / p95 ms | p50 change |
| --- | ---: | ---: | ---: | ---: |
| mysql-strict | 1 | 6.651 / 6.911 | 6.774 / 7.001 | +1.9% |
| mysql-json | 1 | 9.265 / 9.553 | 9.418 / 10.284 | +1.7% |
| redis-strict | 1 | 5.721 / 6.256 | 5.885 / 6.089 | +2.9% |
| redis-json | 1 | 7.899 / 8.083 | 8.072 / 8.326 | +2.2% |

## Prefetch confirmation

Here prefetch is requested for the same Case inside its timer before begin;
its cost is included. This is not hidden background work or a comparison against
a differently prefetched baseline. Three measured sessions per binary follow
one empty-index warmup.

| Workload | Cases/session | Baseline p50 / p95 ms | Candidate p50 / p95 ms | p50 change |
| --- | ---: | ---: | ---: | ---: |
| mysql-strict | 16 | 5.655 / 6.369 | 5.749 / 6.502 | +1.7% |
| mysql-json | 16 | 7.793 / 8.814 | 8.037 / 9.108 | +3.1% |
| redis-strict | 16 | 4.982 / 5.806 | 4.927 / 6.011 | -1.1% |
| redis-json | 16 | 7.002 / 7.883 | 7.039 / 8.283 | +0.5% |
| mysql-strict | 128 | 5.882 / 6.146 | 6.060 / 6.892 | +3.0% |
| mysql-json | 128 | 8.168 / 8.403 | 8.351 / 8.957 | +2.3% |
| redis-strict | 128 | 6.557 / 7.081 | 5.133 / 5.266 | -21.7% |
| redis-json | 128 | 8.786 / 9.370 | 7.286 / 7.491 | -17.1% |

## Semantic and evidence verification

All 288 sessions (9,376 Cases and 150,016 actual native calls,
including warmups) passed. There were 240 measured sessions and
7,056 measured Cases. Every comparison checked original physical
Source offsets, lengths, hashes, selected inventory positions, ownership,
connection/sequence identities, native operation/status, finite once-only
consumption, exact primary output and complete policy witness coverage. No run
had unmatched/unused dependencies, provisional hypotheses or omitted witnesses.

MySQL JSON comparisons independently validate Target generated UUID/time values
and protected SQL structure; the original raw Target SQL and clocks remain in
the full report. Cross-run semantic fingerprints compare the same physical
Source selection and allowed semantics without requiring permitted timestamps
to be identical across different execution times. Evidence byte counts and
complete raw samples remain in each result file.

## Reproduction and artifacts

Build and copy immutable `traffic-e2e` Release binaries from the two revisions
in separate checkouts before running. Use an empty work directory each time:

```bash
python3 -B scripts/bench-case-execution.py \
  --baseline /path/to/frozen-baseline --candidate /path/to/frozen-candidate \
  --work-dir /tmp/protocol-case-main --case-counts 1 16 128 --queries 16 --repeats 3
python3 -B scripts/bench-case-execution.py \
  --baseline /path/to/frozen-baseline --candidate /path/to/frozen-candidate \
  --work-dir /tmp/protocol-case-small --case-counts 1 --queries 16 --repeats 15
python3 -B scripts/bench-case-execution.py \
  --baseline /path/to/frozen-baseline --candidate /path/to/frozen-candidate \
  --work-dir /tmp/protocol-case-prefetch --case-counts 16 128 --queries 16 --repeats 3 --prefetch
```

Raw developer-local artifacts are retained outside the checkout and are not
committed traffic captures:

- `main`: `/data0/icy/.codex/tmp/pcc-perf-v1/benchmark-results.json`; SHA-256 `a4289425ae4307f1aa193dcb5e7a54f4b6d4192faea4acc596956e796b42d652`.
- `small`: `/data0/icy/.codex/tmp/pcc-perf-small-v1/benchmark-results.json`; SHA-256 `2be316bead7381f908ffd5b1b1deb7de9d94d4d05bf46ae3373a4df4d2600fa3`.
- `prefetch`: `/data0/icy/.codex/tmp/pcc-perf-prefetch-v1/benchmark-results.json`; SHA-256 `1e599d69d7360c7459c374db45d675349285b99f25f5386fc774ef2c7e4ffabc`.

The implementation passed `cargo test` (4,074 passed, 33 existing ignored),
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`CODE_ORG_BASE=origin/master .../check-code-organization` and `git diff --check`.
See [execution contracts](protocol-rule-execution-design.md) for architecture,
supported carrier boundaries and native-only constraints.
