# Redis state contracts for variable loops

A loop is a useful Source diagnosis: timers, polling and work duration can change
how often its body runs. The contract compares the effects of those iterations.
A `loop` label alone cannot prove which effects may disappear or combine.
Declare independently proven effects on each bounded key using `state`:

```yaml
redis:
  keys:
    'chat:streaming:*':
      state: {append: concatenate, expire: refresh}
    'chat:streaming:thinking_block:*':
      kind: identity
      formats: [{prefix: thinking-, hex: 12}]
      state:
        get: {transient: [nil]}
    'chat:streaming:text_block:*':
      kind: identity
      formats: [{prefix: text-, format: decimal}]
      state:
        get: {transient: [nil]}
        set: transition
    'chat:task_streaming:*':
      state:
        get: observe
        set: {reduce: last, fields: [/last_activity_at]}
```

| Operation | Equivalence and retained obligations |
| --- | --- |
| `get: observe` | Repeats/coalesces reads within one proven state. At least one successful delivery is required for each observed state. |
| `get: {transient: [nil]}` | Also allows zero observations of the nil state. Non-nil observations remain required. Only complete nil/bulk responses qualify. |
| `append: concatenate` | Different chunk boundaries preserve every byte in order, returned lengths and all read/reset fences. |
| `expire: refresh` | Refresh counts may vary within a proven lifetime; positive TTL, key existence and causal boundaries remain checked. |
| `set: transition` | Explicit ordinary finite SET transitions. Every write is required; omitting this declaration has the same meaning. |
| `set: {reduce: last, fields: [...]}` | Metadata refresh with declared timestamp leaves. Stable fields and TTL remain exact. Creation/deletion and a delivered current-value GET before each refresh remain required. |

Finite Redis exchanges use the exact Target bytes from supported prior writes.
See [write-to-read delivery](redis-read-back.md).

Use `state.get` for variable read counts.
The metadata SET refresh owner validates its GET/SET pairs together; `get: observe`
is implicit for that reduction. It cannot combine with transient nil.
Timestamp refresh fields must also have a recognized `json.fields` time format.
Arbitrary SET values and business writes have no last-write reduction.

## Polling and conditional work

`GET nil; do a; GET nil; do b; GET value` may become `GET value` only when the
omitted body has no required effects, or every such effect has its own proven
reduction. Logging or checking the same absent key can be transient. An order
write, HTTP call, queue event or finite SQL mutation remains a required dependency.
The loop declaration never erases those obligations.

A read-only key may have 0..N transient nil reads followed by one stable terminal
value. Source must prove the nil-to-value causal boundary. A Target read can
observe that terminal value once required preceding Source-lane work has run;
otherwise it still observes nil. The nil reads are optional and the terminal
value still requires real successful delivery. Without a terminal
Source witness, the engine cannot return one. If Source contains owned SETs,
the live SET/DEL claims gate state changes; future values cannot be borrowed.
Unknown historical values before an owned SET retain finite matching.

A completely nil Source trace also supports zero Target reads, without inserting
a fictional SET or DEL. Actual deletion boundaries remain finite, including
multi-key cleanup whose returned count agrees with the selected key's state.
A state without an original GET witness never borrows an earlier lifetime's read.
Within a proven nil state, pooled GETs and deletions that cannot remove the
selected key may overlap. Multi-key deletion counts must still agree with that
key being absent, and every actual deletion retains its finite delivery gate.
Concurrent accesses require complete Source clocks. All reads and no-op cleanup
remain causal predecessors of a later non-nil observation; a real state-changing
deletion also retains its causal boundary on both sides.

## Buffered flushes

`APPEND a; refresh; APPEND b; refresh` may become `APPEND ab; refresh` when complete
Source proof establishes ordered bytes, no intermediate value boundary and an
unchanged positive TTL. Companion GETs and metadata SETs use their own key-local
contracts. An observed intermediate content value or a reset prevents merging
across that boundary. See [APPEND](redis-append-stream.md),
[TTL](redis-state-observations.md) and [metadata refresh](redis-activity-refresh.md).

## Discover, prove, plan, apply, replay

Failure evidence exposes a `redis_loop_state` candidate for relevant GET, SET,
APPEND, EXPIRE or native state/boundary failures, including an earlier lane
blocker. This is a diagnosis hint, never automatic policy approval. Inspect the
earliest Target admission failure and Source's full loop, condition, timer,
writers, readers and cleanup before selecting effects.

Attach independent Source file:line proof to each proposed key declaration.
`rule plan --file <proposal> --evidence <current-id>` checks the complete immutable
Source scope and freezes the policy diff; inspect that plan, apply it with the
returned command and perform fresh genuine fast Replay. Source proof rejects
conflicting users/protocols, Global/shared ownership, unsupported writers,
transactions, TTL observations, malformed/truncated responses or ambiguous clocks.
Each Case and physical endpoint/database/authentication identity remains isolated.

`redis.allowed_state_omissions` lists original transient nil observations that
were not delivered, their rule and reason. Those exchanges remain unconsumed and
unmatched. They supply no physical delivery receipt or input timing prerequisite.
Real deliveries use `state_observations` audits; actual failures and in-flight
calls retain their normal failure and drain obligations. Omission audits are
bounded to 1000 entries with an explicit omitted count. Existing key, call,
observation, epoch and value-size limits remain enforced.

## Replaying a completed API after policy changes

Use `backend-rewrite verification request --focused --api /api/v1/responses
--reason 'Redis state policy changed'` to invalidate the prior API success and
request ordinary fresh Replay of its existing complete cases. Follow the returned
`next` command. This also recovers an idle API queued in a final sweep that cannot
start because the sealed run contains an incomplete input. The request retires
that final admission without accepting it; it cannot discard active repairs,
pending plans or an in-flight operation. Other APIs and verification obligations
remain outstanding. The final full sweep still requires complete sealed Source
evidence and its own accepted review.
