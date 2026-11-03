# Redis observations within a key state

Buffered APPEND calls can change their batch boundaries while preserving every
byte. Per-batch current-block reads and TTL refreshes then change counts too.
APPEND equivalence alone does not authorize those calls. The two explicit
contracts below require complete, Case-local Source proof before changing
observation matching. They never authorize extra SET, DEL, list mutation or
content bytes.

## Current generated identity

Declare the scalar identity format, `read_back: true` and `state.get` on one key pattern:

```yaml
redis:
  keys:
    'task:current:*':
      kind: identity
      formats: [uuid]
      read_back: true
      state: {get: observe}
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

Another ordinary Case may read or write the same concrete key. Its records
neither supply state proof or observation slots nor invalidate the current
Case's proof. It keeps its own responses and finite consumption. A Case with
only historical reads cannot borrow another Case's SET or Target value. Within
the current Case, unsupported mutations and expiry observers remain invalid;
Global/shared or reusable inventory retains its separate ownership boundary.
This permission does not simulate state across Cases.

Only unconditional SET, GET, successful DEL/UNLINK and positive TTL refreshes
are supported in the owned state. Implicit expiry, unknown writers or mutations,
ambiguous script key access, transactional lanes, overlapping ownership and
ambiguous clocks reject the proof. No partial permission is installed.

At runtime a GET uses the currently claimed Source SET/DEL state and the Target
identity already bound by the matched SET. It cannot take an identity from a
future SET or return a previous identity after DEL. Repeated GETs in that state
can use the same Source witness; one successfully delivered GET covers the
equivalent Source observations of that state. A state never observed by Target
still has unused Source reads, except explicit `get: {transient: [nil]}` observations;
see [state contracts](redis-state-contracts.md). All mutations retain ordinary finite matching.

## Positive TTL refresh

```yaml
redis:
  keys:
    'task:stream:*': {state: {expire: refresh}}
```

The proposed key proof must establish one fixed positive TTL and the selected
Case's state boundaries without incompatible expiry observations. Key-local
APPEND and expiry permissions can share one entry; actual physical resources
remain independent.

All selected Source EXPIREs must return integer 1. A successful ordinary Case
SET, APPEND or list creation can establish the key; an initial successful EXPIRE
can instead prove that the key already existed, without knowing its value or
creator. Earlier Case-local accesses retain finite delivery requirements. Their
request order uses the ordinary Redis admission rule: a claimed Case request
in `Responding` satisfies order even while response completion is being recorded.
Pooled reads and writes may therefore proceed without racing that bookkeeping.
Unclaimed, failed and client-termination requests still block later accesses;
final consumption and initial refresh eligibility still require delivery.
The TTL and complete arguments stay exact. A Target cannot cross an unmatched
creation or refresh after a proven DEL, change seconds, add NX/XX options or
borrow a refresh from a future lifetime. Initial existing-key refreshes retain
an actual Target refresh and a bounded runtime observation window.
One successfully delivered refresh covers equivalent Source EXPIREs of that
lifetime; additional refreshes use the same proven response.

A matched unconditional `SET key value EX seconds` (or whole-second `PX`)
can also establish that same TTL for a closed, unchanged scalar lifetime. If
Source only GETs and refreshes that value until a successful single-key
DEL/UNLINK, and both Source and Target delete before the initial TTL, omitting
every refresh preserves the observable state. This covers a buffered text block
created and finalized in one Target flush where Source needed two flushes.
The creation, ordinary reads and deletion must actually complete; pending or
failed deliveries do not earn coverage. Target timing uses a monotonic clock
from creation admission through deletion delivery. Coverage is installed only
after successful closure and completion of all required key reads. A bare SET,
different TTL, compound read/delete, intervening value mutation, unclosed
lifetime or expired deadline retains the ordinary refresh obligation. A later
SET or another lifetime cannot supply this proof. Content and list work remain
independent and retain every ordinary consumption requirement.

The same closed scalar proof also supports the opposite buffering change:
Source needs no explicit EXPIRE, while Target flushes twice and refreshes the
existing pointer. The delivered TTL-bearing SET proves the positive response;
no Source EXPIRE record is manufactured. Target must refresh the exact key
established by that SET with the exact whole-second TTL and no extra options.
Creation must finish delivery first. Every finite Source read and the single-key
deletion still must complete, and Target must close before the original TTL.
A pending or failed actual refresh, a missing finite dependency, or late closure
keeps the Case dirty. No future creation or already deleted state can supply it.
Keys without that complete proof retain ordinary finite matching.

Source proof excludes TTL/PTTL/expiry observations, unsupported key mutations,
implicit expiration, mixed TTLs, stateful lanes and conflicting ownership within
the selected Case. Global/shared inventory remains separate. The
Source key lifetime and runtime observation window must remain below the
smallest proven positive TTL. SET/DEL lifetime transitions and every ordinary
content/list write still match and deliver through their existing owners.

## Evidence and diagnosis

Both contracts are opt-in and bounded to 128 profiles, 4096 Source observations
and 4096 Target observations per Case. Each profile has at most 1024 states.
Responses and raw SET values are bounded to 64 MiB. Every actual delivery remains
tracked even when concurrent reads share a Source witness. Transport failure
keeps the Case dirty; it cannot be hidden by another successful observation.
A prepared Case cannot acquire additional records. Loading another ordinary
Case, including one that writes the same key, cannot change installed proof or
consume its observations. Later Global/shared overlaps retain their rejection.

`redis.state_observations` contains at most 1000 audits with rule, Case, key
fingerprints, Target admission index, original Source witness, state-changing
Source command and covered Source count. Omitted rows are counted separately.
Initial-TTL coverage adds `coverage.kind: initial_expiry_until_delete`, the
Source deletion, TTL and measured Target lifetime. Its Target admission index
identifies the actual deletion; it does not claim an EXPIRE was executed.
An actual extra refresh uses `coverage.kind: initial_expiry_refresh`, references
the real Source SET as its witness and the proven Source deletion, and covers
zero Source observations. Its admission index identifies the Target EXPIRE.
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
