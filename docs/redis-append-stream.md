# Redis APPEND batch equivalence

Redis `APPEND key value` appends bytes to a string and returns its new byte
length. Applications may buffer streaming text before calling it. A Source-proven
`append_stream: true` permits different nonempty chunk boundaries while
preserving the ordered bytes. Declare a bounded key family:

```yaml
redis:
  keys:
    'content:*': {append_stream: true}
```

In an annotated plan proposal, attach independent Source proof of the selected
Case's writes, response lengths, ordered buffering and read/reset boundaries. The
runtime policy omits proof metadata. Resource and database selectors are not
authored; preparation and runtime preserve each actual endpoint, database,
authentication identity and Case key, including pooled connections.

The declaration grants no process ownership, shared inventory, snapshot renewal
or additional non-APPEND calls. Existing proven identity formats may translate
a generated key; they never transform stream text. Use `localcache.requests`
or `process_dependencies.tasks` only for separately proven dependency lifetimes.
The stream selector consumes complete key identities already accepted from
typed metadata, such as a JSON `_content_key`; it cannot infer a new key pair.
JSON metadata heartbeat GET/SET loops have separate explicit
[activity refresh](redis-activity-refresh.md) permission; APPEND alone never grants it.
An APPEND owned by a stream cannot fall back to ordinary matching and consume
its Source exchange without advancing the stream's byte cursor.

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
cannot merge across them. A reset's value/options remain byte exact. The first
successful APPEND response supplies the initial length by subtracting its
appended byte count. A nonempty preexisting value is supported without learning
its contents or borrowing its creation from another Case. Later responses must
agree with that base plus this Case's appended bytes; captured resets establish
new bases. APPEND never manufactures a read of the unknown prefix.

Successful unconditional positive EXPIRE/PEXPIRE refreshes remain ordinary finite
exchanges with exact arguments and responses. Chunk equivalence does not permit
changing, skipping, merging or adding these refresh calls. They require a separate explicit
[state observation or expiry refresh](redis-state-observations.md) proof
to authorize count equivalence. Other commands keep
their ordinary matching, timing and consumption contracts. Unknown mutations,
transactional/watched sessions, ambiguous Source ordering, failed APPENDs and
Global/shared inventory or conflicting Case-local authentication ownership do
not gain stream permission. Another ordinary Case's access to the same key is
outside this proof: it neither contributes bytes nor invalidates the stream.
Script exclusions use Redis's declared nonempty `numkeys` inventory; missing or
unknown key declarations stay conservative. Source proof must cover all writers,
including script key use within the selected Case. A prepared Case's inventory
cannot be extended; loading another ordinary Case cannot change its proof or
consume its byte ranges. Global/shared inventory retains its separate boundary.
Captured APPEND response delays are charged once when a Source exchange is first
reserved; a merged call sums those delays and later pieces of an already charged
Source exchange add no duplicate delay.

Planning validates complete selected Source traces, original successful RESP
lengths and pooled-writer causality with the same preparation used by runtime.
It freezes original request/dependency artifacts and preserves stale checks.
Source self-validation does not prove independent Target behavior: Apply always
requires a fresh genuine Replay with existing recordings. Use the coordinator's
ordinary `rule plan --file ... --evidence ...` and returned Apply command.

Bounds are 64 MiB per nonempty chunk, 64 MiB of Source bytes and 128 keys per Case,
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

A read/reset at the wrong byte cursor is reported as
`redis_append_stream_boundary_mismatch`. It identifies the rule, key fingerprint,
current `source_offset`, `required_source_offset`, `missing_bytes`, and original
Source barrier command/sequence. A premature MGET is a boundary mismatch with
available Source evidence. It claims no read or bytes; after the missing writes
complete, Target can retry the ordinary finite read.
