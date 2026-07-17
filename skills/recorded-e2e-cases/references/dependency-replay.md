# Dependency Replay Contract

Read this reference when wiring or diagnosing case-owned dependency behavior.

## Genuine Target Calls

Recorded E2E MUST execute the target's genuine dependency interfaces,
production adapters, and real protocol clients. Intercept or explicitly route
their emitted traffic to recorder-owned replay listeners. Do not reach
production resources, and do not replace dependency calls with project-local
fixtures, fakes, in-process mocks, or recording-backed implementations.

Only recorder-owned replay consumes `dependencies.jsonl`. The target harness
constructs inbound requests from `request.json` and reads
`expected-response.json` only for final assertions.

## Request And Touch Contract

Build every inbound request from its case `request.json`, including method, URI
and query, applicable headers, and body. Remove only transport headers the
harness must regenerate. Do not hardcode case-specific auth, tenant, query, body,
or cookie values in target tests.

Treat recorder dependency summaries and final replay reports as the acceptance
evidence for case-owned touches. Equivalent target behavior must preserve the
dependency role, compatible operation and input, ordering or state when
relevant, response or error semantics, and required side effects. Different
source code or harmless protocol formatting does not by itself imply a mismatch.

Classify ambiguous dependencies only from source ownership, bootstrap timing,
recorder metadata, or replay evidence. Required side effects remain required.
Replay-policy version one cannot waive unused case exchanges as background
noise; re-record or keep the case incomplete instead of inventing an exception.

## Coverage

Completion requires no unexplained unmatched target calls, unused case
exchanges, unsupported or unsafe dependency operations, or missing required
side effects. HTTP response compatibility alone is insufficient.

Use `dependencies-summary.json`, when present, as a human and agent checklist;
do not make target project code parse it to decide behavior or manufacture
completion. Use `dependencies-debug.jsonl` only to explain missing semantic
capture or protocol failures, never as the primary replay source.

## Protocol Evidence

For MySQL, match semantic exchanges by the business target host and port,
database or schema, and username or role before normalized SQL and parsed
parameters. Preserve transaction, lock, repeated-call, and session order when
required. Use semantic column metadata for schema evidence; missing SQL,
prepared parameters, column schema, or untruncated rows is a recording risk.

For Redis and Memcached, preserve connection-lane ordering and protocol
semantics. Unmatched, unsupported, unsafe, and unused evidence remains dirty.

For Kafka, use the recorder-supported client profile and semantic produce,
delivery, and fetch evidence. Match stable topic, key, headers, and value
semantics. Transactions, authentication, compression, unsupported APIs, unsafe
captures, or broker errors remain incomplete unless the recorder explicitly
supports them.

For other dependency types, require recorder-supported semantic input, output,
ordering, and error evidence. Do not synthesize downstream HTTP payloads, cache
values, queue messages, rows, or side effects from the expected response.

## Metrics

Treat recorded push metrics as dependency side effects and validate them through
replay when supported. Validate pull metrics through the target exporter or
scrape surface. Do not write recorded metric payloads from target fixtures. If
metrics evidence is absent or unsupported, report the recorder gap or obtain
explicit approval for a behavior-contract change.
