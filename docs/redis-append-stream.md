# Redis APPEND batch equivalence

Redis `APPEND key value` appends bytes to a string and returns its new byte
length. Applications may buffer streaming text before calling it. A Source-proven
`redis_append_stream` effect permits different nonempty chunk boundaries while
preserving the ordered bytes. It is disabled unless an explicit rule selects
the API, Redis endpoint/database/authentication identity and bounded key family.
State belongs to one Case and Source key, including ordinary pooled connections.

```yaml
id: task-content-append
match:
  api: POST /tasks
  resource: {protocol: redis, endpoint: 'cache.test:6379', database: 0}
  operation: APPEND
  key: {kind: affix, prefix: 'content:'}
effect: {kind: redis_append_stream}
proof:
  source: src/storage.py:append_buffer
  fact: >-
    Source buffers one Case-owned ordered byte stream. Scheduling determines
    chunk boundaries; reads and mutations delimit observable byte prefixes.
    There are no unrecorded or concurrent writers to these keys.
```

Use `resource.username` when the Source Redis identity has a username. Conditions
may additionally select an immutable inbound request body. Independent APIs need
their own Source proof. The rule grants no process ownership, shared inventory,
snapshot renewal or additional non-APPEND calls. Existing proven identity rules
may translate a generated key; they never transform stream text.

For Source writes `ab`, `cd`, a Target may write `a`, `bcd`; its responses are
`:1` and `:4`, rather than Source's `:2` and `:4`. Matching compares the next
literal byte prefix and records the Source fragment ranges. A byte mismatch or
overrun claims nothing. A partially delivered Source exchange remains unused;
successful delivery of all its byte ranges is required for consumption. Transport
failure retains a dirty Case. Partial strings with no pending transport do not
hold the interaction close barrier open as an in-flight network response.

GET, MGET, length/range reads, expiry observations and mutations fence the stream
at their original Source byte boundary. A Target cannot read early or append past
an unclaimed fence. SET/SETEX/PSETEX and DEL/UNLINK establish new epochs; an APPEND
cannot merge across them. A reset's value/options remain byte exact. Initial
string length must be proven by the APPEND integer response and any captured
successful reset; an unknown nonempty initial value is unsupported.

Successful unconditional positive EXPIRE/PEXPIRE refreshes remain ordinary finite
exchanges with exact arguments and responses. Chunk equivalence does not permit
changing, skipping, merging or adding these refresh calls. Other commands keep
their ordinary matching, timing and consumption contracts. Unknown mutations,
transactional/watched sessions, ambiguous Source ordering, failed APPENDs and
overlapping Case/Global/authentication ownership do not gain stream permission.
Script exclusions use Redis's declared nonempty `numkeys` inventory; missing or
unknown key declarations stay conservative. Source proof must cover all writers,
including script key use. Prepared stream inventory cannot acquire later touches.
Captured APPEND response delays are charged once when a Source exchange is first
reserved; a merged call sums those delays and later pieces of an already charged
Source exchange add no duplicate delay.

Planning validates complete selected Source traces, original successful RESP
lengths and pooled-writer causality with the same preparation used by runtime.
It freezes original request/dependency artifacts and preserves stale checks.
Source self-validation does not prove independent Target behavior: Apply always
requires a fresh genuine Replay with existing recordings. Use the coordinator's
ordinary `rule plan --file ... --evidence ...` and returned Apply command.

Bounds are 1 MiB per nonempty chunk, 16 MiB of Source bytes and 128 keys per Case,
4096 Source APPENDs per key, 4096 successful Target chunks per Case, and 64 Source
fragments per Target call. `redis.append_streams` exposes at most 1000 audit rows
with Source connection/sequence/ranges, Target observation identity, returned
length and payload/key fingerprints. `append_streams_omitted` counts omitted
rows. Reports contain no stream bytes. Recording files remain unchanged.

A rejected byte prefix is reported as `redis_append_stream_mismatch`, rather
than missing Source evidence. It includes the rule, the Target observation and
payload digest, the stream cursor, remaining Source bytes, the first differing
absolute byte offset, and the next Source connection/sequence when bytes remain.
Overruns and extra writes after the stream is exhausted use the same diagnostic;
the failed request reserves no bytes. These facts locate the rejected write;
earlier failed reads or writes may still be the cause. Source preparation and
unsupported-evidence failures retain `evidence_unavailable`.
