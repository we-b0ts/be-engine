# Replay case performance after built-in time semantics

Measured on 2026-10-31, after the shared standard-time comparison and business capture configuration changes.

- Baseline: frozen release binary `87ca5e37aba2`. Its product code is identical to the task's initial `d56d4fc7` baseline; the intervening changes contain documentation only.
- Candidate: release binary `274a3bf80203`.
- Baseline SHA-256: `0ba3263f870807b132a17bbc206f0d18581c44fc19080ee34f9c7bc32e034ffa`.
- Candidate SHA-256: `6fcea348f9fd6b9e5016ebaffadb4db2057578cacc9f52a92796a529c4f8e3d6`.
- Both binaries use the same optimized Cargo profile and target-runtime identity. No compilation or test process ran during measurement.

Each complete synthetic case includes lazy preparation, request begin, a real HTTP request whose target performs 16 native Redis/MySQL calls, independent exact status/content-type/body assertions, and case end acknowledgement. The dependency timer is part of the HTTP request timer. Phase p50 values do not add up to the complete-case p50.

The two binaries receive byte-identical Source files and separate persistent index directories. One empty-index session per binary/workload is warmup; three subsequent sessions per binary are measured. Binary order alternates. OS page-cache state is uncontrolled.

## Complete case elapsed time

Times are milliseconds. Each cell contains p50 / p95 across the measured cases.

| Workload | Cases/session | Baseline p50 / p95 | Candidate p50 / p95 | p50 change |
| --- | ---: | ---: | ---: | ---: |
| mysql-strict | 16 | 5.685 / 6.462 | 6.008 / 6.928 | +5.7% |
| mysql-json | 16 | 7.967 / 9.112 | 8.174 / 9.366 | +2.6% |
| redis-strict | 16 | 4.752 / 5.824 | 4.907 / 5.957 | +3.3% |
| redis-json | 16 | 6.970 / 8.417 | 7.260 / 8.341 | +4.2% |
| mysql-strict | 128 | 5.969 / 6.199 | 6.313 / 6.557 | +5.8% |
| mysql-json | 128 | 8.382 / 9.227 | 8.467 / 8.725 | +1.0% |
| redis-strict | 128 | 5.029 / 5.151 | 5.181 / 5.337 | +3.0% |
| redis-json | 128 | 7.191 / 7.359 | 7.500 / 7.624 | +4.3% |

The measured p50 increase is 0.085–0.344 ms per case. The task treats 1–5% changes as small variation to record without further optimization rounds. MySQL strict remains 5.7–5.8% higher and is retained as an observed cost, rather than described as unchanged performance.

The candidate skips SQL schema inference when a response has no columns. Request validation, time comparisons, independent witnesses and finite consumption remain fully executed. This guard removes work with no possible metadata output; the table reports the combined final behavior.

## Phase and resource measurements

Values below are medians for 128-case sessions. CPU includes Replay startup and finalization, with 10 ms resolution. RSS is process peak memory.

| Workload | Prepare p50 ms | Dependency p50 ms | End p50 ms | Replay CPU ms/session | Replay peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| mysql-strict | 2.925 → 3.091 | 2.344 → 2.503 | 0.188 → 0.191 | 910 → 960 | 106.25 → 108.50 |
| mysql-json | 3.534 → 3.557 | 4.119 → 4.186 | 0.196 → 0.192 | 1190 → 1210 | 109.50 → 110.25 |
| redis-strict | 2.284 → 2.335 | 2.114 → 2.206 | 0.125 → 0.133 | 830 → 860 | 98.50 → 99.25 |
| redis-json | 2.353 → 2.377 | 4.197 → 4.482 | 0.129 → 0.133 | 1060 → 1100 | 90.25 → 90.25 |

## Integrity and scope

All 64 sessions, 4,608 cases and 73,728 actual native dependency calls passed, including warmups. There are 3,456 measured cases.
Every sample checks original Source offsets, lengths, hashes, connection/sequence identities, selected positions, operation/status, complete sealed witness coverage, and once-only consumption. Unmatched and unused counts are zero; no provisional pre-match is used. Original files and frozen binary hashes are checked before and after execution. All paired semantic digests agree.

These workloads cover HTTP primary input with MySQL UPDATE/OK or Redis GET/bulk, plus JSON values using declared UUID and numeric Unix-time contracts. Standard string-time matching, TLS, HTTP dependencies, PB, Motan, Memcached, concurrency and the complete managed assertion adapter matrix are covered by relevant functional tests where supported; this experiment does not measure their performance. It uses a loopback synthetic target rather than production containers.

Functional validation for this code revision: `cargo fmt --check`, `cargo test --no-fail-fast` (4145 passed, 33 existing ignored), `cargo clippy --all-targets -- -D warnings`, and the code-organization check against `origin/master` all passed.

## Reproduction

```bash
python3 -B scripts/bench-case-execution.py \
  --baseline /path/to/frozen-baseline --candidate /path/to/frozen-candidate \
  --work-dir /tmp/time-policy-case-performance \
  --case-counts 16 128 --queries 16 --repeats 3
```

The work directory must be empty. It retains raw samples, reports, original synthetic Source files and per-binary index artifacts; generated data and CA files stay outside the repository.

