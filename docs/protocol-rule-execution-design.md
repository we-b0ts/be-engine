# Protocol, codec, rule and Replay execution contracts

Task: `1032990_1#105761` (`3mAYhJylTs`). Baseline: `0609b37e`.

The architecture covers HTTP and Motan primary inputs; HTTP, Redis, MySQL,
Memcached, Motan and the existing constrained Kafka dependencies; Scalar, JSON
and Protobuf payloads; and the existing value, ownership and native stateful
rules. HTTP inputs with Redis/MySQL JSON, time and identity contracts are the
first complete verification slice. That slice does not constrain the types or
extension contracts.

The main performance outcome is the wall time from scheduling one Case through
actual input execution, independent response assertions and acknowledged Case
end. Lazy loading, dependency matching, delivery, evidence durability and cleanup
remain inside that measurement whenever they occur inside the Case. Preparation
and final batch publication are also reported separately.

## Independent responsibilities

| Owner | Contract |
| --- | --- |
| Primary protocol | Native API identity, immutable original inputs, real input execution and independent output observation. HTTP and Motan delegate to their existing native drivers. |
| Dependency adapter | Native references, resource/operation identity, candidate access, ordering/transaction guards and actual delivery state. No generic method can manufacture consumption. |
| Content codec | Immutable schema preparation, typed value views, presence, original wire remainder and authorized re-encoding. |
| Value rule | Shared time/identity/collection semantics, Source proof requirements and comparison or delivery proposals. |
| Preparation | Bind applicable rules, native indexes, codecs, scope and evidence locations into an executable Case view. |

Each protocol or codec family uses an enum implementing a narrow trait. The
enum dispatches to concrete native implementations. Shared interfaces return
fixed view/plan types; variant-specific native state stays inside its variant.
The architecture does not instantiate the Cartesian product of all protocols,
codecs and rules, and does not require a `dyn` call per compared field.

Native framing, MySQL transactions, Redis lanes and Pub/Sub, Memcached quiet
commands/CAS and Motan one-way/request IDs retain their existing owners. Content
decoding does not grant permission to alter those facts. Primary completion,
asynchronous business completion and complete capture are separate observations.

## Shared execution authority

Resource adapters supply protocol facts and explicit native constraints. They
do not own an independent copy of finite admission, delivery completion or
consumption. `DependencyProvider` describes native resource/operation identity,
value-slot support and preparation. Its purpose is to project facts consumed by
the engine, not to route a request to a protocol-owned `process()` implementation.
Native framing and encoding retain the existing protocol libraries and drivers.

`replay/admission` owns the shared finite claim, delivery receipt, terminal
transaction, cancellation and notification mechanisms. Redis, MySQL and Memcached
use this authority for ordinary finite requests. A wire receipt can be published
without waiting for the Replay mutex; evidence/semantic commit and final
consumption remain separate. A shared finish transaction runs native commit hooks
and changes the finite state once. Failed commit, cancelled delivery and stale or
duplicate completion cannot create a successful consumption receipt.

The generic request executor calls behavior-oriented
`DependencyRequestAdapter` hooks: observe once, select from projected native
facts, describe a required barrier, and report the selected/rejected outcome.
It owns lock boundaries, registration, waiting, cancellation, deadlines and
retry sequencing. Protocol adapters do not each implement a private copy of
that loop. Physical Target arrival indexes use the shared request-order owner;
response completion order cannot rewrite them.

The internal `NativeDependencyAdapter` is only a read-only view of recorded
delivery references. Its `protocol()` reports identity for inventory/diagnosis;
it is not the request execution interface and does not select a private
protocol-owned workflow.

Admission and delivered-value barriers are separate contracts. A request already
claimed in an ordinary Case can satisfy admission ordering before delivery
bookkeeping obtains the mutex. Rules that depend on delivered values still wait
for the stronger barrier. Protocol-specific transactions and quiet responses
select their required native constraints; they do not reimplement claim
transitions or invent delivery. Wait registration occurs under
the same ownership lock as its predicate, and retries retain the original Target
observation, arrival index and clocks. Case epochs, cancellation and deadlines
bound the shared wait.

Connection framing/authentication/session data stay native. Target connection
termination, request ownership, Case cancellation, finite claims and lane
progress use shared contracts. This avoids adding a single global write lock:
independent connections and lanes continue to progress concurrently.

Conformance includes the historical pooled-request race, cross-command lane
barriers, failed semantic commit after actual wire delivery, cancellation of an
optional run-owned slot and independent raw-field rejection. A shared semantic
or concurrency fix must pass these tests across the installed resource adapters.

## Preparation and execution

Preparation produces three related contracts:

1. Execution requirements: applicable rules, typed fields, native guards,
   independently observed clocks and staged identity/value proposals.
2. Index requirements: native resource/operation partitions, relevant rule groups,
   codec schemas, field extraction and original evidence locations.
3. Evidence requirements: original Source references, independent protected Target
   observations, complete attempted hypotheses and actual delivery receipts.

The compiled rule and adapter capability declarations must agree before execution.
An unsupported combination has a stable reason. A feature consumed by a native
stateful executor is explicitly assigned to that executor, not acknowledged by
an empty successful generic implementation.

A Case execution view reuses immutable prepared objects. Switching Cases updates
epoch, scope and live consumption state without rebuilding indexes for all
previous Cases. Deferred loading installs only its newly loaded ranges. Missing
or failed preparation is an explicit error, never an empty dependency inventory.

The request pipeline preserves these stages:

```text
native query and actual Target observation
  -> ordered candidate cursor
  -> native admission guards and complete strict comparison
  -> bounded diagnostic hypotheses, only after all strict stages fail
  -> tentative claim and value/identity proposals
  -> required evidence durability and actual native delivery
  -> original native completion/consumption commit
```

Exact and rule-compatible candidate postings retain original Source order. An
exact fingerprint cannot jump ahead of an earlier Source exchange that matches
an authorized time/identity contract. Hypotheses retain ambiguity and budget
failures; no truncated candidate set can establish uniqueness. Native lane
blockers cover preceding operations even when their command differs.

## Index and cache boundaries

| Artifact | Contents | Invalidation inputs |
| --- | --- | --- |
| Physical catalog | Stable effect IDs and exact offsets, lengths and hashes | Original Source content and recording/index schema |
| Scope view | Membership under the frozen ownership decision | Original catalog and applicable attribution snapshot |
| Native candidate index | Resource, operation and safe native structural keys; ordered record positions | Source range, native adapter semantics and index schema |
| Rule dispatch | Applicable rule groups and selectors | Relevant selector and semantic fingerprints |
| Codec/field plan and pure projection | Schemas, typed paths, SQL tokens and immutable decoded Source values | Payload identity, extractor version, codec schema and relevant field plan |
| Evidence locator | Original effect and physical/decoded field coordinates | Original identity and slot extractor version |

The physical catalog is independent of time/identity policy changes. Ownership
changes affect scope membership; they do not rewrite original capture or its
physical positions. Rule and schema changes invalidate their dependent plans,
without using one global policy revision to rebuild every artifact.

Candidate keys must admit every valid match. Values allowed to change under time
or identity rules cannot act as fixed rejection keys. Coarse indexes return a
superset; complete rules and native guards establish actual eligibility. Candidate
discovery is not ownership proof or a delivery receipt.

Reuse current physical-location readers, bounded pages, native candidate indexes,
SQL projection caches and prepared codec plans. Build missing immutable metadata
in a streaming preparation pass. Avoid duplicated full-ledger selectors, complete
JSON tree copies, scope reparsing after payload-cache eviction and runtime scans
of unrelated Cases. Target parsing is shared within one request. Cached Source
syntax and field projections never cache live clocks, identity decisions or
consumption across sessions.

## Value fidelity and extension coverage

JSON and PB expose common value contracts while retaining native type and
presence. PB schema bindings, repeated/packed fields, unknown fields and original
wire remainders remain strict. Explicit codec selection is required; a mismatch
cannot silently choose another format. Existing unsupported PB identity bindings
remain explicitly unsupported until a separately tested implementation admits
them. Memcached/Motan native replay support similarly does not imply support for
every codec or authored rule in those carriers.

Direct MySQL `CompiledRule` value plans currently have no installed live route
and are explicitly rejected, including Protobuf combinations. Current MySQL
requests use native SQL effects and global JSON/physical field formats. Pure
codec conformance is distinct from a complete protocol replay capability.

Capability coverage includes role, protocol/version, carrier, codec, value
capability and execution stage. Closed enums require explicit treatment when a
feature is added. Shared conformance tests exercise supported combinations and
verify stable rejection for unsupported ones. Native-only features retain their
original integration tests.

## Verification

The per-Case preparation summary describes only that Case's effective immutable
Source inventory. Its rule and format entries are selector-eligible requirements;
the native operation, value and session guards still prove each actual match.
Startup and Process inventories remain prepared by their session owners. A Case
summary does not prove coverage of those run scopes, and does not duplicate their
inventory or reinterpret their ownership.

Preserve genuine response values, selected physical Source occurrences, ordering,
finite consumption, identity bijections and evidence coverage in differential
tests. Cover strict matches, authored time/identity rules, rejected hypotheses,
ambiguity, incomplete evidence, failed delivery and deferred installation.

Measure per-Case latency under equal cache/prefetch conditions, including misses,
and report p50/p95 alongside CPU, peak RSS, candidate visits and evidence costs.
Separate preparation from the Case without hiding work lazily performed by
`begin`. Increase unrelated inventory independently of the active Case to verify
that its candidate lookup and switching work do not grow with the whole batch.
Actual HTTP-to-Redis/MySQL execution and independent primary-response assertions
are required; an inventory-only workload is not a Case execution benchmark.

Required repository checks are `cargo fmt --check`, `cargo test`,
`cargo clippy --all-targets -- -D warnings`, `git diff --check`, and
`CODE_ORG_BASE=origin/main plugins/ai-engine/skills/be-replay/scripts/check-code-organization`.

The completed implementation passed 4,074 default tests with 33 existing ignored
tests. Regression coverage includes the shared Redis/SQL literal/SQL-argument/
Memcached time-and-identity contract, native wire delivery races, reversed lane
completion, optional cancellation debt, pre-delivery cancellation, RPC/echo
handoff, report finalization and source-scope digest consistency.
