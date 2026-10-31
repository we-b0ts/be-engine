# Rule candidate pre-matching

Managed Replay defaults to `project.replay.pre_match: true`. A supported
dependency request difference can use a temporary rule hypothesis to continue
the Case and collect later differences. The policy and recording remain
unchanged. A hypothesis always leaves the Case dirty, even when the primary
response matches. Source proof, ordinary rule plan/apply and fresh Replay are
required before verification can pass.

The shared typed hypothesis kernel covers complete JSON UUID and request-clock
leaves, MySQL SQL literal slots and prepared statement arguments, Redis scalar or
JSON arguments, and UUID segments in Redis keys. SQL structure and binding, scalar
types, JSON members and array order, Redis command/options and unexplained bytes
remain strict. Arbitrary numeric IDs, counters, strings and TTL values are not
assumed dynamic. Existing authored contracts retain their failures; a hypothesis
cannot override them.

Every adapter exhausts strict matches first. Pure previews evaluate bounded
candidates without consuming Source inventory or committing identity bindings.
Exactly one eligible candidate is required before a real claim. Multiple possible
candidates leave an explicit ambiguity; the engine does not pick the first match.
Repeated identities retain the shared case-local bijection across JSON, SQL and
Redis carriers. Provisional rules do not authorize ownership changes, response
reuse, missing calls, additional calls or relaxed lane order.

`dependency_hypothesis_attempts` retains every considered hypothesis, including
rejected and unselected probes and a partially explained request that ultimately
failed. `dependency_pre_matches` identifies hypotheses that actually influenced
delivery. An unused or rejected guess alone does not make an otherwise strict
passing request provisional. Every entry has its actual observation identity,
original native coordinate, candidate rule, result, selection state and Source
proof requirement. Values remain in protected evidence; summaries use types,
shapes and digests.

Selected diagnostic delivery waits for authenticated hypothesis evidence and the
protected Target request to become durable. The bounded writer batches persistence
outside Replay's state lock. A persistence failure refuses diagnostic delivery,
retains the failure and stops claiming complete evidence coverage. Final, failed
and recoverable interrupted attempts expose the same queryable journal; evidence
budget exhaustion is explicit rather than silently truncating the attempted rules.

`backend-rewrite dependency-attribution show --api /route` returns a bounded API
projection and exact continuation commands. It distinguishes a value hypothesis,
no resource/operation candidate, an ownership fence and an actual consumption
failure. Cross-case discovery is an investigation hint, not permission to serve
another API's response. Source proof and batched plan/apply follow a diagnostic
run; changes to actual matching or execution require one fresh affected-scope Replay.

Ordinary request-header differences remain dirty observations without interrupting
an otherwise matched HTTP exchange. A true unmatched or unsupported dependency
still interrupts the Case. If another dependency fails later, header observations
remain in dirty evidence rather than the execution-failure list.
Explicit header-format validation retains its existing
contract and must not be confused with an SDK metadata observation.

```yaml
project:
  replay:
    pre_match: true
    http_stream_timing: fast
```

Set `pre_match: false` for strict rejection without hypotheses. Low-level replay
accepts `--pre-match` (or `replay.pre_match` in its configuration file); callers
using the library lifecycle API retain strict defaults unless they opt in.

## Streaming dependency timing

Managed Replay defaults to `http_stream_timing: recorded`. Opt into `fast` for
time-insensitive streams: complete successful HTTP dependency streams deliver
their recorded headers, chunks and EOF without sleeping through recorded offsets.
Byte contents, chunk order, trailers,
backpressure and real transport completion remain checked. Original stream
metadata and recorded clocks are never rewritten.

Incomplete streams and Source-stop, cancellation and server-close prefixes keep
their recorded timing and termination behavior. No synthetic EOF completes a
prefix. Keep `recorded` for elapsed-time checks, debounced persistence, heartbeats,
cancellation races and timeout behavior. Compressing arrival gaps can change the
number and order of native dependency calls; such mismatches remain failures or
dirty evidence and cannot be waived as an expected consequence of acceleration.
Low-level replay accepts
`--http-stream-timing fast|recorded` and retains recorded timing by default.

## Exact Source dependency references

For a blocked lane, inspect the case's dependency summary and select the returned
target detail. MySQL and Redis details expose an `exchange_query` command template.
Supply the diagnostic's Source connection ID and sequence to inspect that exact
exchange, including exchanges outside the representative sample window:

```text
backend-rewrite --target-root <target> case dependencies <case-dir> <target-id> \
  --connection-id <source-connection-uuid> --sequence <source-sequence>
```

The sequence is Redis `sequence` or MySQL `query_sequence`. Both reference parts
and the dependency target are required; missing or ambiguous matches fail instead
of widening the query. The result uses the existing bounded value previews and
does not change recordings. A physical reference identifies captured I/O; callers
still trace Source code to establish ownership and expected business behavior.

New MySQL matched observations and dirty-cluster `target_matches` include
`source_connection_id` and `source_query_sequence`. Use that pair with the
exact-reference command above. `recorded_index` (or the raw report's `index`)
is an internal exchange index, not a query sequence. Historical reports without
these references do not establish a wire identity from the index alone.
