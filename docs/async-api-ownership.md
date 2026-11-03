# Reusable asynchronous API ownership

An asynchronous API has two separate contracts. Its `when`, `when_response`,
`unless_response` and `end` declarations control the capture lifetime. Its optional
`ownership` declaration identifies finite dependency requests produced by that
input, including requests captured after the declared end or inside a later
Case's admission window. Neither contract proves actual Target consumption.

Resolve a repeated ownership issue in this order:

1. Inspect the authenticated recording's selected-rule provenance. New
   `async-api-observation.json` files retain group/scenario fingerprints and
   hashed terminal metadata. A missing older receipt means unknown; wall time or
   a different composite capture hash does not establish whether a particular
   rule was applied.
2. Trace the actual Source branch. Returning a queued response, sending work to
   an executor, releasing a cancellation key and finishing all cleanup can be
   different events. Later callback ingress remains its own input.
3. Publish a reusable ownership declaration or a corrected lifecycle through the
   ordinary Source-backed rule plan/apply transaction. Inspect complete Source
   scope and existing Target evidence, then perform genuine Replay.
4. If a complete policy still leaves unresolved traffic, keep the existing
   independent Source proof and exact-UUID attribution path available. A policy
   executor defect does not authorize ignoring traffic or creating consumption.

## Declaration

This abbreviated example belongs under an existing `async_api` scenario:

```yaml
ownership:
  proof:
    source: jobs.py:dispatch
    fact: The detached finalizer reads the result for its uniquely created assistant row.
  origin:
    resource: {protocol: mysql, endpoint: db.test:3306, database: app, username: writer}
    tables: [work_items]
    row_match: {role: ASSISTANT}
    bindings: {task: task_id, subtask: id}
  requests:
    - protocol: redis
      resource: {protocol: redis, endpoint: cache.test:6379, database: 0, username: default}
      operation: GET
      arguments: [{identity: subtask, prefix: 'result:'}]
```

All bindings come from one unique, successful, committed, explicit-column Source
INSERT in the original input. Repeated or uncommitted creation does not establish
an origin. The request and response must select the scenario in its original
ordered position. Each request must resolve one origin in the same process epoch.

MySQL requests declare a concrete SQL template, exact resource, permitted physical
tables or table patterns, and a zero-based scalar-placeholder-to-binding map.
`{{table}}` denotes one declared physical table and its corresponding aliases;
`?` denotes one scalar, never a table or SQL fragment. An explicitly declared
`transaction_member: true` can cover an ID-free statement only inside a complete
transaction whose other members are also declared and whose identity-bearing
members agree on one origin. Native boundaries retain their transaction and
wire-order checks. At most the immediately adjacent, successful zero-effect idle
ROLLBACK inherits that closure.

Redis requests declare an exact resource, command and argument count. Arguments
can be literal strings, bounded identity templates, explicit non-authoritative
`{any: true}` values, or JSON pointers with literal/identity constraints. JSON
selection does not change the actual PUBLISH body. A declared EVALSHA may include
`script_exists_prelude: true`; only its unique immediately preceding successful
SCRIPT EXISTS for the same SHA on the same connection can inherit the origin.

These are ownership permissions, not request/value comparison exemptions.
Business payloads, native order, finite delivery and response assertions remain
with their existing Replay owners. Competing inputs referencing the same
identity, unknown request bodies, mixed transactions, gaps and overlapping origins
retain explicit unresolved membership. Bounded diagnostic samples never truncate
that authoritative membership.

## New and historical recordings

Before a new recording is sealed, Recorder runs the same deterministic Source
classifier used by historical materialization. It changes derived capture
ownership, preserves the physical observed/admitted Case, UUID, protocol identity,
clocks and payload bytes, and seals `dependency-ownership.json` with the original
capture metadata. It rebuilds all central offsets, hashes, scopes and semantic
counts before publishing the manifest. Startup, independent Process and Shutdown
ownership cannot be reassigned by an API descendant declaration.

Historical recordings stay byte-identical. Their authenticated complete inventory
is projected into external scope views. The cache is bound to the sealed Source,
policy and compiled ownership executor. It considers every original scope even
when the original unowned count is zero. Current independently proved manual
decisions take precedence over automatic ambiguity; a partial manual proof leaves
the remaining UUIDs pending. A changed effective ownership snapshot requires
fresh real Replay.

Local Source explanations remain plan evidence and do not enter published runtime
policy or alter runtime fingerprints. These declarations follow existing reviewed
Source policy semantics; the launch entrypoint hash is not a full Source code
closure identity. A Source change can introduce a new caller or branch requiring
review and a policy update.

## Completion and rollout

Ownership of captured requests cannot prove that an unobserved asynchronous task
has finished. In particular, an in-memory completion after parallel callbacks
has no universal final network operation. Do not extend an end to an arbitrary
last observed GET, infer completion from a quiet interval, or treat clean scopes
as proof that every future callback was captured. Actual incomplete capture and
missing lifecycle evidence retain their existing obligations.

New recording containers must contain a binary that supports the ownership
declaration and load the updated policy. Updating the host `backend-rewrite`
symlink only upgrades host-side orchestration. A container with an engine copied
into its image must be rebuilt and recreated before it consumes the new policy.
Verify the binary revision and the new sealed receipts, then inspect the actual
effective scopes and Replay results.
