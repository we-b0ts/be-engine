# Recorded candidate/evidence comparison

Baseline: `a0b5cf6`. Candidate: `324c1be` (including `182834d`). Both use the
same optimized Rust test harness and policy snapshot on the same host. Each API
runs in a fresh process, three times per version, with builds excluded from the
measurement. Values below are medians. Recording batch: `20261016030056`.

| API | Source cases | Captured MySQL requests | Matching and metadata, before → after | Speedup |
| --- | ---: | ---: | ---: | ---: |
| `/api/plugins/installed/sync-device` | 12 | 824 | 27.991 s → 5.352 s | 5.23× |
| `/api/tasks/*` | 6 | 1,906 | 28.877 s → 8.032 s | 3.60× |

Source preparation is separate: sync-device improves from 3.467 s to 2.702 s;
tasks improves from 0.678 s to 0.469 s. Sealing, publication serialization and
verification improve from 0.646 s to 0.292 s and 1.941 s to 0.392 s respectively.
Startup remains approximately 1.37 s / 1.05 s for these warmed recording indexes.

| API | Report bytes, before → after | Total generated evidence, before → after | Peak RSS, before → after | Process CPU time, before → after |
| --- | ---: | ---: | ---: | ---: |
| sync-device | 7,901,949 → 1,591,279 | 75,010,669 → 10,169,202 | 361.0 → 263.4 MiB | 33.30 → 9.66 s |
| tasks | 21,203,208 → 887,790 | 35,990,948 → 10,557,608 | 538.3 → 128.1 MiB | 32.51 → 9.87 s |

Total evidence includes the public report, private observation directory and all
encrypted payload segments. It excludes original recordings and reusable Global
inventories. Thus moving the directory out of the report does not hide its cost.
Totals decrease by 86.4% and 70.7%, while retaining more evidence for sync-device.
The manifest itself has bounded counters/references; tests check its serialized
size independently of the complete directory.

## Semantic and evidence checks

All three baseline/candidate runs produce the same per-API semantic digest:

- sync-device: `2d403f83e1d2ae06f01787832de3cc109df87dc3710080832be1b429666ea801`
- tasks: `d076b62249af584a2946a70d130027ead496f13ccaf013126bdc1863cf58774e`

These digests cover selected exchange indexes, materialized response contents,
PREPARE metadata, builtin/unmatched outcomes, remaining Case exchanges and rule
statistics. Matched counts are unchanged (409 / 951). They are engine-stage
results, not API HTTP assertions or a new successful full application Replay.

Sync-device observes 4,914 witness entries in both versions. Baseline omits
2,007 entries at its payload limit; candidate omits zero and verifies complete
coverage. Tasks observes 4,450 entries with zero omissions in both versions.
Fresh candidate manifests and their complete directories/chunks are authenticated
through the production evidence reader. All 59 recording/input files are
checksummed before and after each version and remain unchanged.

The old sync-device Replay omitted later Target payloads, so its 824 retained
MySQL requests are a labelled subset. All 12 original Source cases still load.
No missing Target request is synthesized from Source. Tasks uses the 1,906
retained MySQL requests from its complete published witness inventory. Captured
Case/request clocks are restored identically to isolate time-sensitive matching.

Run preparation and fresh-process measurements with
`scripts/prepare-recorded-replay-benchmark.py` and
`scripts/bench-recorded-replay-performance.py`; see
[the engine-stage procedure](replay-candidate-performance.md).
Raw inputs/logs contain sensitive SQL and stay in private external directories;
only this aggregate comparison is committed.
