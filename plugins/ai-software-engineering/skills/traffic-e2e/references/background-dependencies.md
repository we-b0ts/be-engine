# Background Dependency Classification

Use when process-owned traffic is mixed into cases or must replay local state.

## Ownership Model

Classify by causality, not by timing alone:

- `runtime_state`: process work whose responses build response-driving local state;
- `independent`: process work unrelated to selected responses and side effects.

Treat Motan background rules as `independent` only. If an asynchronous Motan
result is consumed by business behavior, it is not eligible for this rule even
when a scheduler owns the call; repair the normal target initialization or
refresh path instead. AI proves ownership and independence from source and
runtime evidence. Recorder does not infer either fact from timing, repetition,
threading, or protocol.

Apply `runtime_state` during response repair when evidence proves Replay must
serve it for target-local state. Classify `independent` only after responses
pass. Timing, a shared host, or an unused exchange is not ownership proof.

## Replay Scope

New recordings have two dependency scopes:

```text
<case>/dependencies.jsonl
<run>/global-dependencies.jsonl
```

Global contains startup and rule-matched dependencies. Exchanges are consumed
once; repeated scheduler cycles need repeated records. Replay prefers Case,
then Global.

Recorder adds:

```text
global_dependency_reason = bootstrap_window | background_rule
global_dependency_phase = bootstrap | runtime
global_dependency_matched_by = bootstrap_window | <rule-name>
global_dependency_response_role = independent | runtime_state  # background rules only
```

Bootstrap rule matches use `reason=background_rule`, `phase=bootstrap`.
Unruled ready-time idle traffic stays only in `traffic.jsonl`. Replay has no
legacy bootstrap fallback.

## Supported Rules

The current narrow rule types are:

- exact HTTP authority, method, and path prefix with
  `response_role=independent`;
- exact Vintage service group plus Motan interface and method, always
  independent and with no endpoint, Vintage alias, or payload persisted in the
  rule;
- Redis `ZCOUNT` with `response_role=independent`, one stable service port set,
  and exact key prefix and suffix, with no hostname persisted in the rule;
- Redis `GET` with `response_role=runtime_state`, one stable service port set,
  an exact bounded key list, and an initial-load observation timeout;
- Breeze-backed Memcached `get` with `response_role=runtime_state`, one exact
  resolved resource identity, and a bounded numeric key series
  `<start..end><separator><suffix>` whose numeric bounds are unsigned 64-bit.

Recorder observes completed replay-safe runtime-state matches from process
startup. Redis counts each configured exact key once; Memcached counts every
matching completed response. After HTTP ready, Recorder observes each applied
rule for up to `initial_load_timeout_ms`; no rule means no wait. It logs
progress every 10 seconds and warns but continues case admission when the load
remains incomplete. Replay does not wait for target-local initialization;
repair target startup or readiness when that causes a response difference.

Only Global exchanges explicitly emitted by a background rule with
`response_role=runtime_state` use connection-independent replay. They remain
single-use and require the exact recorded target, command, and arguments, but
earlier unrelated commands on the source connection cannot block them. Case,
bootstrap-only, independent, and legacy exchanges retain connection-order
semantics.

Supply the logical resource to `plan|apply`. The tool requires one compatible
`mc` descriptor, persists its stable identity without the dynamic port, and
resolves the port when the source-created descriptor is available. Recorder
may start while the identity is pending and binds the first matching event
after the descriptor appears. Runtime uses port only as a coarse filter, then
exact `get` and bounded key-series matching. Every configured identity must be
resolved when the source HTTP ready probe succeeds; a missing descriptor at
that boundary is a source or recording-configuration readiness error.

## Evidence-Gated Commands

For source-proven independent HTTP traffic, preview one exact selector:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root <target> \
  --name <stable-background-rule-name> \
  --authority <exact-authority> \
  --method <exact-method> \
  --path-prefix <exact-path-prefix> \
  --case-source <exact-finalized-case-source> \
  --api '<canonical-api-group>' \
  --source-revision <same-source-revision> \
  --evidence '<source file/symbol and ownership explanation>'
```

Review the selector and matched case IDs, then repeat with `apply`. The command
requires at least one matching unused case exchange, rejects selectors that
also match unmatched or unsupported target requests, and replans from current
config and evidence before writing atomically.

For source-proven independent Motan process traffic:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root <target> \
  --protocol motan \
  --name <stable-background-rule-name> \
  --group <exact-vintage-service-group> \
  --interface-name <exact-interface> \
  --method-name <exact-method> \
  --case-source <exact-finalized-case-source> \
  --api '<canonical-api-group>' \
  --source-revision <same-source-revision> \
  --evidence '<source file/symbol and independence explanation>'
```

The selector is the exact Vintage service group plus Motan interface and method;
the Vintage cluster is derived from the interface as `<interface>/service`.
Planning requires a matching unused case Motan exchange and rejects the RPC
command when it also appears as unmatched, unsupported, or unsafe target
traffic. Apply uses the same arguments.

For source-proven independent Redis process traffic, use the stable service
port set rather than domains. Repeat `--port` for every source-proven member of
the logical service group:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root <target> \
  --protocol redis \
  --name interest-tag-mining-cache-refresh \
  --port 20917 \
  --port 20918 \
  --port 20919 \
  --command ZCOUNT \
  --key-prefix '1042015:' \
  --key-suffix '.wtm2' \
  --case-source <exact-finalized-case-source> \
  --api '<canonical-api-group>' \
  --source-revision <same-source-revision> \
  --evidence '<source file/symbol and independence explanation>'
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

For response-driving Redis startup reads, provide every exact key and select
`runtime_state`:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root <target> \
  --protocol redis \
  --name startup-cache-warm \
  --port 20917 \
  --command GET \
  --key cache:init:a \
  --key cache:init:b \
  --response-role runtime-state \
  --initial-load-timeout-ms 60000 \
  --case-source <exact-finalized-case-source> \
  --api '<canonical-api-group>' \
  --source-revision <same-source-revision> \
  --evidence '<source file/symbol and response-driving state explanation>'
```

Planning requires a finalized version-6 report and replay-safe matching unused
Global evidence for every configured key. Unmatched requests are expected while
diagnosing missing startup state, but unsupported or unsafe traffic on the
selected ports and command remains a hard rejection. Apply uses the same
arguments, then create a new standard recording; existing artifacts do not gain
runtime-state metadata retroactively.

For a Memcached `runtime_state` rule, preview before applying:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root . \
  --protocol memcached \
  --name planet-video-cache-warm \
  --breeze-resource user-video \
  --command get \
  --key-start 0 \
  --key-end 4095 \
  --key-separator . \
  --key-suffix pl_video \
  --initial-load-timeout-ms 60000 \
  --case-source <exact-finalized-case-source> \
  --api '<canonical-api-group>' \
  --source-revision <lowercase-git-revision> \
  --evidence '<file>:<symbol> scheduled local-cache warm'
```

`apply` uses the same arguments. Planning requires a finalized replay report,
matching unused case or Global exchanges, immutable dependency records, a
unique Breeze descriptor, replay-safe keys and responses, and no same-port
`get` traffic reported as unsupported or unsafe. Unmatched requests are
allowed while diagnosing the missing runtime state. Apply rechecks the config,
report, dependency evidence, and descriptor port before its atomic write.
The observation window defaults to 60000 ms and starts when the source HTTP
ready probe succeeds. Recorder logs incomplete progress as a warning and
continues case admission when the window elapses.

After any rule change, create a new standard recording. Never reclassify or
edit an existing artifact.
