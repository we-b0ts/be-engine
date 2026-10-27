# Redis observations within a key state

Buffered APPEND calls can change their batch boundaries while preserving every
byte. Per-batch current-block reads and TTL refreshes then change counts too.
APPEND equivalence alone does not authorize those calls. The two explicit
contracts below require complete, Case-local Source proof before changing
observation matching. They never authorize extra SET, DEL, list mutation or
content bytes.

## Current generated identity

Declare the scalar identity format and `read_back: true` on one key pattern:

```yaml
redis:
  keys:
    'task:current:*': {kind: identity, formats: [uuid], read_back: true}
```

The engine retains actual Case, endpoint, database, authentication and protocol
partitions internally. No authored API/resource/database, binding or
`state_epochs` field is needed. Only current raw SET identity to GET is covered
by this key-local state permission; additional native list/compound contracts
retain their own finite behavior.

An annotated plan requires Source proof for complete owned SET/DEL lifetimes,
causal clocks and variable read counts, including a positive write-to-read
witness. Published policy omits that evidence. Historical GETs before the first
supported successful SET keep their finite slots and fence the first mutation;
a profile without an owned SET gains no reusable reads. Within an owned state,
GET must equal the latest SET value or nil after DEL.

Another Case's ordinary finite single-key GET may touch the same concrete key.
It supplies no state proof or observation slots to the writing Case, and keeps
its own recorded response and finite consumption. A Case with only historical
reads cannot borrow another Case's SET or Target value. Foreign mutations,
expiry observers, shared/reusable reads and Global inventory still reject the
owned state proof; this permission does not simulate state across Cases.

Only unconditional SET, GET, successful DEL/UNLINK and positive TTL refreshes
are supported in the owned state. Implicit expiry, unknown writers or mutations,
ambiguous script key access, transactional lanes, overlapping ownership and
ambiguous clocks reject the proof. No partial permission is installed.

At runtime a GET uses the currently claimed Source SET/DEL state and the Target
identity already bound by the matched SET. It cannot take an identity from a
future SET or return a previous identity after DEL. Repeated GETs in that state
can use the same Source witness; one successfully delivered GET covers the
equivalent Source observations of that state. A state never observed by Target
still has unused Source reads. All mutations retain ordinary finite matching.

## Positive TTL refresh

```yaml
redis:
  keys:
    'task:stream:*': {expiry_refresh: true}
```

The proposed key proof must establish one fixed positive TTL, complete owned
lifetimes and absence of expiry observers or external writers. Key-local
APPEND and expiry permissions can share one entry; actual physical resources
remain independent.

All selected Source EXPIREs must return integer 1 on a key established by a
successful ordinary Case SET, APPEND or list creation. The TTL and complete
arguments stay exact. A Target cannot refresh before creation or after DEL,
change seconds, add NX/XX options or borrow a refresh from a future lifetime.
One successfully delivered refresh covers equivalent Source EXPIREs of that
lifetime; additional refreshes use the same proven response. A lifetime with
no Target refresh retains its unused Source refreshes.

Source proof excludes TTL/PTTL/expiry observations, unsupported key mutations,
implicit expiration, mixed TTLs, stateful lanes and overlapping ownership. The
Source key lifetime and runtime observation window must remain below the
smallest proven positive TTL. SET/DEL lifetime transitions and every ordinary
content/list write still match and deliver through their existing owners.

## Evidence and diagnosis

Both contracts are opt-in and bounded to 128 profiles, 4096 Source observations
and 4096 Target observations per Case. Each profile has at most 1024 states.
Responses and raw SET values are bounded to 1 MiB. Every actual delivery remains
tracked even when concurrent reads share a Source witness. Transport failure
keeps the Case dirty; it cannot be hidden by another successful observation.
Prepared inventory cannot acquire later overlapping records, except another
Case's ordinary finite GET under the read-back partition described above.

`redis.state_observations` contains at most 1000 audits with rule, Case, key
fingerprints, Target admission index, original Source witness, state-changing
Source command and covered Source count. Omitted rows are counted separately.
No identity values or stream bytes appear in these audits. Admission failures
use `redis_state_observation_mismatch` with the state-changing Source command;
they are distinct from missing or invalid Source evidence.

For a remaining streaming failure, start with the earliest Target admission
index. Verify APPEND byte cursors before assuming an unmatched MGET is missing
identity translation. A rejected current-state read can prevent later block
creation, and an exhausted per-batch refresh can stop the rest of that batch.
Response/SSE equality does not establish dependency convergence.

Use the normal native rule planner and Source preflight. Existing finite
read-back and read-commutation rules retain their semantics unless explicitly
updated. New or updated policy requires fresh genuine Replay; Source self
validation does not certify the Target.
