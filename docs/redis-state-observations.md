# Redis observations within a key state

Buffered APPEND calls can change their batch boundaries while preserving every
byte. Per-batch current-block reads and TTL refreshes then change counts too.
APPEND equivalence alone does not authorize those calls. The two explicit
contracts below require complete, Case-local Source proof before changing
observation matching. They never authorize extra SET, DEL, list mutation or
content bytes.

## Current generated identity

Enable the explicit runtime permission on the raw SET-to-GET read-back:

```yaml
read_back:
  - operation: GET
    write_operation: SET
    argument_index: 1
    state_epochs: true
```

The containing identity rule retains its explicit API, resource, database,
user and bounded key selector. Original write capture, references and read-back
contract remain in place. Only raw SET identity to GET supports `state_epochs`;
JSON fields and list reads keep their finite contracts.

The ordinary rule plan/apply transaction accepts this one-way addition to an
already installed finite read-back declaration. Keep the declaration in its
original position and preserve its write/read contract. In the submitted plan
proposal, attach a separate local `proof: {source: ..., fact: ...}` to this
read-back declaration. Its evidence describes complete Case-owned SET/DEL
lifetimes and variable read counts. The plan freezes that evidence separately;
published `policy.yaml` contains only `state_epochs: true`. Removing an installed
state permission is rejected by additive updates. Planning checks the complete Source trace again and
Apply requires fresh genuine Replay.

Source must start absent and prove every GET
equals the latest SET value or nil after DEL. Only unconditional SET, GET,
successful DEL/UNLINK and positive TTL refreshes are supported on these keys.
Implicit expiry, unknown initial nonempty values, other mutations, unknown
scripts, transactional lanes, overlapping Global/Case/user ownership and
ambiguous clocks reject the complete proof. No partial permission is installed.
The declaration retains the ordinary positive write-to-read proof across its
selected Source inventory; a Case whose selected key stays absent may use its
proven nil state without inventing a write.

At runtime a GET uses the currently claimed Source SET/DEL state and the Target
identity already bound by the matched SET. It cannot take an identity from a
future SET or return a previous identity after DEL. Repeated GETs in that state
can use the same Source witness; one successfully delivered GET covers the
equivalent Source observations of that state. A state never observed by Target
still has unused Source reads. All mutations retain ordinary finite matching.

## Positive TTL refresh

```yaml
id: task-stream-ttl
match:
  api: POST /tasks
  resource:
    protocol: redis
    endpoint: cache.example:6379
    database: 0
    username: default
  operation: EXPIRE
  key: {kind: affix, prefix: 'task:stream:'}
effect: {kind: redis_expiry_refresh}
proof:
  source: app/session.py:1210
  fact: >-
    Buffered writes refresh one fixed positive TTL. Scheduling changes the
    refresh count; this Case has no expiry observer or external key owner.
```

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
Prepared inventory cannot acquire later overlapping records.

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
