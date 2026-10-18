# Process-Owned Dependency Classification

Use when process-owned asynchronous traffic is mixed into case ownership.

## Ownership Model

A process-owned dependency rule proves only that matching asynchronous work is process-scoped
and case-independent. It carries no classification of whether the response
affects business state. AI proves process ownership from source and runtime
evidence; timing, repetition, scheduler names, shared hosts, and unused
exchanges are not proof.

Response causality remains a target concern. When source and case evidence show
that a process-owned dependency drives local state, the target AI must implement
the source-compatible initialization, refresh, cache, fallback, and readiness
behavior. A process-owned dependency rule cannot replace or hide that implementation.

## Replay Scope

New recordings have two dependency scopes:

```text
<case>/dependencies.jsonl
<run>/global-dependencies.jsonl
```

Global contains startup and rule-matched dependencies. Replay prefers Case,
then Global. Ordinary exchanges are consumed once. A Redis exchange marked as
the seed of a run-local cache snapshot is reusable for repeated matching reads.

Recorder adds:

```text
global_dependency_reason = bootstrap_window | background_rule
global_dependency_phase = bootstrap | runtime
global_dependency_matched_by = bootstrap_window | <rule-name>
```

Bootstrap rule matches use `reason=background_rule`, `phase=bootstrap`.
Unruled ready-time idle traffic stays only in `traffic.jsonl`. Replay has no
legacy bootstrap fallback.

Finalized recordings also contain `source-process-traffic-summary.json`. It
separates pre-readiness observations from configured process-owned rules and
reports protocol, endpoint, operation, and bounded counts. Redis snapshot
sections additionally report seeds, reuses, fill failures, and those counts by
intercepted domain and port. Backend-rewrite projects this summary as the
top-level `source_process_traffic` action context; treat it as a source-path
diagnostic hint, not proof of ownership or response causality.

## Supported Rules

MySQL reclassification also reconciles value-rule applicability using the exact
Source case/exchange occurrences stored in new Replay reports. A rule selected
only by unused process-owned traffic no longer leaves an API obligation. Any
remaining business occurrence or actual Target use remains checked. Restoration
and rule removal restore the original obligation. Reports without occurrence
proof require fresh Replay; ownership is never inferred from rule ids alone.

The current narrow rule types are:

- MySQL read-only SELECT templates scoped to exact host, port, database, username
  and exact tables, bounded numeric shards, or single-wildcard table identifier
  patterns; see [MySQL replay](../../../../../docs/mysql-replay.md)
  for evidence-gated plan/apply and table-bound column alias templates. The
  coordinator can reclassify complete unused Case evidence with the current
  rule and reuse the recording without changing its JSONL;

- exact HTTP authority, method, and path prefix;
- exact Vintage service group plus Motan interface and method, with no endpoint,
  Vintage alias, or payload persisted in the rule;
- Redis `ZCOUNT` with one stable service port set and exact key prefix and
  suffix, with no hostname persisted in the rule;
- Redis `GET` with one stable service port set, an exact bounded key list, and
  an initial-load observation timeout;
- Redis bootstrap `HGET`/`HMGET` with a stable service port set, optional exact
  keys, bounded numeric-middle key patterns, and the exact field sequence;
- Redis process-owned `HSCAN` with a stable service port set and exact keys or
  bounded numeric-middle key patterns. Cursor and scan options are not part of
  the selector;
- Breeze-backed Memcached `get` with one exact
  resolved resource identity, and a bounded numeric key series
  `<start..end><separator><suffix>` whose numeric bounds are unsigned 64-bit.

Recorder can observe completed replay-safe initial-load matches from process
startup. Redis GET counts each configured exact key once; Memcached counts every
matching completed response. After HTTP ready, Recorder observes each rule with
an initial-load timeout for up to `initial_load_timeout_ms`; it logs
progress every 10 seconds and warns but continues case admission when the load
remains incomplete. Replay does not wait for target-local initialization;
repair target startup or readiness when that causes a response difference.

Global exchanges explicitly emitted by any process-owned rule use
connection-independent replay. Ordinary process-owned exchanges remain
single-use. For a configured Redis rule, Recorder instead holds the first
successful response for each logical rule/session/command/argument tuple for
the rest of that run. Only that first exchange is semantic Global evidence;
later snapshot hits remain diagnostic traffic. Replay reuses the marked seed
for every identical target read. The snapshot is bounded and does not cache
Redis error responses. Other case, bootstrap-only, legacy, HTTP, Motan, and
Memcached exchanges retain their existing consumption and connection-order
semantics. This replay treatment does not replace destination behavior.

A previously authorized Redis rule may derive reusable-seed behavior without
editing the recording when its complete snapshot proof is available. It
does so only when every matching exchange has complete replay-safe evidence,
each observed logical target/session/command/argument identity has a
successful `bootstrap_window` Global seed, and all matching Global and Case
responses for that identity are byte-consistent. The bounded overlay references
the original exchange and is regenerated from the current rule and case source;
errors, truncation, conflicts, incomplete configured-key coverage, or ambiguous
Global ownership reject the whole rule overlay.

Supply the logical resource to `plan|apply`. The tool requires one compatible
`mc` descriptor, persists its stable identity without the dynamic port, and
resolves the port when the source-created descriptor is available. Recorder
may start while the identity is pending and binds the first matching event
after the descriptor appears. Runtime uses port only as a coarse filter, then
exact `get` and bounded key-series matching. Every configured identity must be
resolved when the source HTTP ready probe succeeds; a missing descriptor at
that boundary is a source or recording-configuration readiness error.

## Unified Authorization

A process-owned selector is a typed rule in the policy named by `project.policy`.
During managed rewrites, use the returned discovery/capability evidence and the
single rule transaction described in [unified rules](replay-policy.md):

```yaml
id: configuration-refresh
match: {}
effect:
  kind: process_owned
  source_revision: ''
  selector:
    protocol: http
    authorities: [config.example]
    methods: [GET]
    path_prefixes: [/refresh]
proof:
  source: src/config/refresh.rs:42
  fact: A process scheduler refreshes this endpoint independently of API handlers.
```

```bash
backend-rewrite --target-root <target> rule plan \
  --file /tmp/process-rule.yaml --evidence <current-evidence-id>
backend-rewrite --target-root <target> rule apply <plan-id>
```

The full updated policy supplies origin and conflict context; only proposed
rules receive new authorization. Source validation enumerates the complete
finalized recording, including sibling Cases and Global evidence. Apply checks
that inventory again. Global evidence never impersonates a Case origin.
Truncated captures, incomplete MySQL result rows and failed ownership evidence
cannot authorize a selector.

API-triggered asynchronous work uses the `origin` contract with explicit
request conditions, captures and nested proofs. Transaction members and Redis
script selectors use their typed domain owner. Follow the returned schema;
do not flatten an origin into a broad process permission.

Classification-only changes can rebuild a derived report without modifying
JSONL. Snapshot-producing Redis GET selectors require fresh recording under the
current conservative authorization boundary. Capture plugins also require
fresh recording to verify their output; scope and complete Source input alone
are not plugin output evidence. Preserve any Replay obligation returned by the
plan. An older retained snapshot overlay is never silently promoted by a new
classification rule.

Unbounded unused-host exemptions are retired. A finite-sharing rule is a
separate bounded cross-case delivery permission and does not authorize unused
work. Implement Source-compatible refresh, readiness and cache state in the
Target even when the traffic is process owned.
