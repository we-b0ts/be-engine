# Rule candidate pre-matching

Managed Replay defaults to `project.replay.pre_match: true`. A supported
dependency request difference can use a temporary rule hypothesis to continue
the Case and collect later differences. The policy and recording remain
unchanged. A hypothesis always leaves the Case dirty, even when the primary
response matches. Source proof, ordinary rule plan/apply and fresh Replay are
required before verification can pass.

The initial capability covers complete JSON UUID and timestamp leaves in shared
request value adapters. Object members, array lengths, scalar types and all
unexplained values remain strict. Existing authored contracts retain their
failures; hypotheses cannot replace them. SQL statement identifiers, Redis
commands/keys/options, protocol identity, finite consumption and lane order stay
with their existing owners. Unsupported differences still fail the current Case.
Additional scalar, TTL, encoding and read-back mechanisms can be added separately.

HTTP and Redis selection exhaust strict matches before considering a hypothesis.
Previews are bounded and publish candidate evidence only when their exchange is
selected and its ordinary identity decision commits. Repeated identities retain
the shared case-local bijection. Provisional permissions never authorize a
process-owned exclusion, a reused snapshot, missing calls or additional calls.

`dependency_pre_matches` in the Replay report records case IDs, stable candidate
IDs, actual JSON pointers, proposed policy fragments and value digests. It does
not persist raw value tokens. Dirty-cluster evidence includes these observations
and their requirement for Source proof. The same candidate ID can occur at
multiple observations, allowing one proof/plan to address several locations.
Continuing execution is diagnostic; it does not establish that a proposed field
is semantically generated or that later behavior is independent of the hypothesis.

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
