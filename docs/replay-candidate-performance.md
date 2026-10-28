# Candidate matching and policy evidence

HTTP attachment witnesses support complete bodies up to 64 MiB **per body**.
The envelope budget includes base64 expansion for both request and response,
plus 1 MiB of metadata. Original JSONL record budgets also cover worst-case
JSON escaping of two UTF-8 bodies. Dependency summaries and Source rule proofs
use that same record budget; diagnostic case files and preflight Source traces
have a separate 1 GiB limit. These limits do not enlarge JSON/Protobuf value
codec budgets, expose payloads in summaries, or permit truncated bodies.

MySQL scopes are indexed by Case/Global origin, endpoint, normalized session
identity and compatible command family. Text queries and prepared execution
remain compatible; PREPARE exchange lookup is separate from result metadata
lookup. The original Case-before-Global and exact/projection/semantic order is
unchanged. Availability, dynamic values and policy decisions are evaluated live.
Static lexer output uses an 8 MiB/1024-entry process cache; parameters, clocks,
bindings and successful matches never enter it. Large statements keep their
original uncached parsing capability.

Source request and response envelopes refer to original semantic record ranges,
checksums and file identities. Recorder's existing proof selectors/locations are
reused when available; old indexes fall back to a thin identity scan without
allocating response rows. Native adapters reconstruct and verify the same
envelope when a rule needs it. Recordings remain immutable and must remain
available for rule evidence; replacing, removing or moving a referenced original
fails explicitly. Archive the recording alongside its Replay, or keep its
original managed location available.

Compact witnesses retain each physical Target request, including zero-candidate
and failed requests. Consecutive candidate visits are grouped in original order
and authenticated at snapshot/seal. Duplicate visits do not create another pair.
Every candidate can still be expanded for discovery and plan; only storing the
winning candidate would be insufficient. Preflight builds a borrowed Source
identity index once rather than scanning the entire candidate graph per record.
The final version-4 manifest contains only coverage counters, digests and artifact
references. Its complete private observation directory is sealed separately and
authenticated by the session key. Readers authenticate that directory before
expanding any proof; publication and plan freezing carry all referenced files.

Actual Target payloads are encrypted in chunks of at most 1 MiB. A 64 MiB segment
limit rotates storage instead of omitting evidence. Sealing/publication/readers
validate segment identities, contiguous ownership, chunk checksums, plaintext
digests, observation roles and candidate membership. Large Source values need
no copied payload; large Target values use multiple chunks. Dependency requests
and derived dependency responses use the same protected payload mechanism.
API-response plans continue to use their existing Source/actual-response artifact
references and assertion validation. A derived delivery remains explicitly
distinct from independent Target observation.

The observation and candidate-count bounds still protect session memory.
One session retains at most 262,144 Source and Target observations combined,
and 1,048,576 candidate associations. Its authenticated private directory has
a 512 MiB metadata budget shared by publication and readers. These limits
cover ordinary 70-100 Case API batches, including late unmatched requests;
they do not change payload encryption, identity or completeness validation.
The observation budget covers every Case
in a focused API; it is not renewed or consumed separately for each Case.
Exhausting such a bound or failing persistence leaves explicit incomplete
coverage; it cannot authorize plan/apply. Disk use for genuine new Target data
is proportional to that data. A compact status is not a promise that arbitrary
large Target payloads consume only kilobytes. Existing v1/v2 evidence remains
readable; v3/v4 require an updated engine reader.

## Recorded engine-stage comparison

`scripts/prepare-recorded-replay-benchmark.py` prepares private inputs from genuine
captured independent Target requests. Use a disposable Python environment with
PyYAML and cryptography. Outputs contain sensitive SQL and must stay outside git.
Supply one `--report` per API and a private `--output` directory.
The policy snapshot keeps MySQL rules and required acquisition, process-owned,
sharing and identity declarations so genuine Global prerequisites still apply.

Build the ignored test in optimized mode for the baseline and candidate, saving
each executable before the next build:

```bash
cargo test --release --lib captured_candidate_and_evidence_performance --no-run
TRAFFIC_E2E_RECORDED_PERF_INPUT=/private/input.json \
TRAFFIC_E2E_RECORDED_PERF_OUTPUT=/private/results.json \
  /path/to/saved-test-executable --ignored --nocapture \
  captured_candidate_and_evidence_performance
```

The same harness restores captured Case/request clocks and measures Source
preparation, matching/metadata lookup and authenticated evidence sealing.
It reads original recordings with their genuine run boundary and confirmed
Global subscriptions. Mutable Replay state/output are private; it does not run
the application, change coordinator state or install host interception. Check
the immutable input hashes before/after. Compare semantic digests, coverage,
payload bytes and per-case timings across repeated runs. These measurements
isolate the engine stages; they are not application HTTP throughput or a full
API correctness verdict. A recording with previously omitted Target observations
only supplies its retained request subset and must be labelled accordingly.

`scripts/bench-recorded-replay-performance.py` runs each API/repeat in a fresh
saved test process, records process CPU/RSS and checks the original input hashes.
Run baseline and candidate sequentially with no build in flight. The measured
[sync-device/tasks comparison](replay-candidate-benchmark.md) includes all private
directory and payload bytes in its storage totals.
