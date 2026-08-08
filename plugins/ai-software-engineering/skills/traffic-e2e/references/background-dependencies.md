# Background Dependency Classification

Use when process-owned asynchronous traffic is mixed into case ownership.

## Ownership Model

A background rule proves only that matching asynchronous work is process-scoped
and case-independent. It carries no classification of whether the response
affects business state. AI proves process ownership from source and runtime
evidence; timing, repetition, scheduler names, shared hosts, and unused
exchanges are not proof.

Response causality remains a target concern. When source and case evidence show
that a background dependency drives local state, the target AI must implement
the source-compatible initialization, refresh, cache, fallback, and readiness
behavior. A background rule cannot replace or hide that implementation.

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
separates pre-readiness observations from configured background rules and
reports protocol, endpoint, operation, and bounded counts. Redis snapshot
sections additionally report seeds, reuses, fill failures, and those counts by
intercepted domain and port. Backend-rewrite projects this summary as the
top-level `source_process_traffic` action context; treat it as a source-path
diagnostic hint, not proof of ownership or response causality.

## Supported Rules

The current narrow rule types are:

- exact HTTP authority, method, and path prefix;
- exact Vintage service group plus Motan interface and method, with no endpoint,
  Vintage alias, or payload persisted in the rule;
- Redis `ZCOUNT` with one stable service port set and exact key prefix and
  suffix, with no hostname persisted in the rule;
- Redis `GET` with one stable service port set, an exact bounded key list, and
  an initial-load observation timeout;
- Redis bootstrap `HGET`/`HMGET` with a stable service port set, optional exact
  keys, bounded numeric-middle key patterns, and the exact field sequence;
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

Global exchanges explicitly emitted by any background rule use
connection-independent replay. Ordinary background exchanges remain
single-use. For a configured Redis rule, Recorder instead holds the first
successful response for each logical rule/session/command/argument tuple for
the rest of that run. Only that first exchange is semantic Global evidence;
later snapshot hits remain diagnostic traffic. Replay reuses the marked seed
for every identical target read. The snapshot is bounded and does not cache
Redis error responses. Other case, bootstrap-only, legacy, HTTP, Motan, and
Memcached exchanges retain their existing consumption and connection-order
semantics. This replay treatment does not replace destination behavior.

Supply the logical resource to `plan|apply`. The tool requires one compatible
`mc` descriptor, persists its stable identity without the dynamic port, and
resolves the port when the source-created descriptor is available. Recorder
may start while the identity is pending and binds the first matching event
after the descriptor appears. Runtime uses port only as a coarse filter, then
exact `get` and bounded key-series matching. Every configured identity must be
resolved when the source HTTP ready probe succeeds; a missing descriptor at
that boundary is a source or recording-configuration readiness error.

## Evidence-Gated Commands

For source-proven process-owned HTTP traffic, preview one exact selector:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root <target> \
  --name <stable-background-rule-name> \
  --case-source <exact-finalized-case-source> \
  --source-revision <same-source-revision> \
  --evidence '<source file/symbol and ownership explanation>' \
  http \
  --authority <exact-authority> \
  --method <exact-method> \
  --path-prefix <exact-path-prefix>
```

Review the selector and matched case IDs, then repeat with `apply`. The command
requires at least one matching unused case exchange, rejects selectors that
also match unmatched or unsupported target requests, and replans from current
config and evidence before writing atomically.

For source-proven process-owned Motan traffic:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root <target> \
  --name <stable-background-rule-name> \
  --case-source <exact-finalized-case-source> \
  --source-revision <same-source-revision> \
  --evidence '<source file/symbol and process-ownership explanation>' \
  motan \
  --group <exact-vintage-service-group> \
  --interface-name <exact-interface> \
  --method-name <exact-method>
```

The selector is the exact Vintage service group plus Motan interface and method;
the Vintage cluster is derived from the interface as `<interface>/service`.
Planning requires a matching unused case Motan exchange and rejects the RPC
command when it also appears as unmatched, unsupported, or unsafe target
traffic. Apply uses the same arguments.

For source-proven Redis ZCOUNT process traffic, use the stable service
port set rather than domains. Repeat `--port` for every source-proven member of
the logical service group:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root <target> \
  --name interest-tag-mining-cache-refresh \
  --case-source <exact-finalized-case-source> \
  --source-revision <same-source-revision> \
  --evidence '<source file/symbol and process-ownership explanation>' \
  redis \
  zcount \
  --port 20917 \
  --port 20918 \
  --port 20919 \
  --key-prefix '1042015:' \
  --key-suffix '.wtm2'
```

The rule is process-level and applies regardless of which API is being
recorded. Ports identify the stable Redis business group; source or fake-DNS
hostnames are diagnostic evidence only and are not written to configuration.
Planning requires a finalized version-6 replay report, at least one matching
unused case exchange, immutable case dependency evidence with a replay-safe
matching key, and no unmatched, unsupported, or unsafe target `ZCOUNT` on the
configured ports. `apply` rechecks the config, replay report, and case evidence
before writing atomically. Use only source-proven group ports; a port need not
be observed in the current sample when source configuration proves it belongs
to the same group. The same named Redis rule may add source-proven ports through
another `plan|apply`, but cannot remove ports or change its command or key
shape. Apply uses the same arguments, then create a new standard recording.

For process-owned Redis GET startup reads, provide every exact key:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root <target> \
  --name startup-cache-warm \
  --case-source <exact-finalized-case-source> \
  --source-revision <same-source-revision> \
  --evidence '<source file/symbol and response-driving state explanation>' \
  redis \
  get \
  --port 20917 \
  --key cache:init:a \
  --key cache:init:b \
  --initial-load-timeout-ms 60000
```

Planning requires a finalized version-6 report and replay-safe matching unused
case evidence for every configured key. Unmatched, unsupported, or unsafe
traffic on the selected ports and command is rejected. Apply uses the same
arguments, then creates a new standard recording.

For source-proven bootstrap hash reads, use the coordinator planner with a
small number of exact exceptions and numeric key shapes rather than enumerating
every observed key:

```bash
backend-rewrite --target-root <target> dependency-rule plan redis hget \
  --evidence-id <pre-readiness-traffic-evidence-id> \
  --name experiment-bootstrap \
  --source-evidence '<source file/symbol and bootstrap ownership proof>' \
  --port 6379 \
  --numeric-key-pattern 'exp:matchlist:<id>' \
  --numeric-key-pattern 'exp:list:<id>' \
  --key traffic-result \
  --field version
```

Use `redis hmget` with repeated `--field` arguments in exact wire order for
HMGET. Planning reads replay-safe `bootstrap_window` exchanges from the
immutable Global dependency file, requires evidence for every exact key and
numeric pattern, and rejects same-command unsafe or unsupported traffic.
Unmatched target requests do not authorize the rule and remain dirty. Apply the
returned plan, then create a fresh standard recording so its first-value seed
is explicit and reusable.

For a process-owned Memcached `get` rule, preview before applying:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root . \
  --name planet-video-cache-warm \
  --case-source <exact-finalized-case-source> \
  --source-revision <lowercase-git-revision> \
  --evidence '<file>:<symbol> scheduled local-cache warm' \
  memcached \
  --breeze-resource user-video \
  --key-start 0 \
  --key-end 4095 \
  --key-separator . \
  --key-suffix pl_video \
  --initial-load-timeout-ms 60000
```

`apply` uses the same arguments. Planning requires a finalized replay report,
matching unused case exchanges, immutable dependency records, a
unique Breeze descriptor, replay-safe keys and responses, and no same-port
`get` traffic reported as unmatched, unsupported, or unsafe. Apply rechecks the config,
report, dependency evidence, and descriptor port before its atomic write.
The observation window defaults to 60000 ms and starts when the source HTTP
ready probe succeeds. Recorder logs incomplete progress as a warning and
continues case admission when the window elapses.

After recorder ownership-rule changes, create a new standard recording. The
rewrite coordinator consolidates Redis rule changes with other pending
recording-contract changes and schedules one fresh recording after runnable API
work drains.
