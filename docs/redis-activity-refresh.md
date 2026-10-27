# Redis JSON activity refresh

Stream flushes and event boundaries can trigger different numbers of metadata
heartbeats while preserving the stream itself. Author this permission separately
from APPEND chunk equivalence:

```yaml
json:
  fields:
    /last_activity_at: {kind: time, formats: [rfc3339]}
redis:
  keys:
    'chat:task_streaming:*':
      activity_refresh: {fields: [/last_activity_at]}
```

An annotated proposal also supplies independent Source file/symbol proof on the
key declaration. The rule does not infer permission from a name or the presence
of repeated GET/SET. Use native `rule plan --file ... --evidence ...`, review its
complete immutable proof and diff, then `rule apply --plan ...`. Applying a rule
requires fresh genuine Replay; offline Source validation is not Target acceptance.

Source preparation covers the complete immutable Redis inventory, partitioned
by Case, endpoint, database, authentication, protocol and concrete key. Each
eligible lifetime starts with a successful unconditional SET using fixed positive
EX seconds. Every GET must return the exact latest Source SET bytes. Subsequent
SETs need a preceding GET, the same TTL/options and object fields; only the
explicit timestamp leaves may vary, using recognized global JSON time formats
inside the existing fixed five-second request window. Missing fields, business
changes, implicit expiration, scripts/unknown commands, TTL observers, stateful
connections, Case-local conflicting ownership, Global/shared inventory or
ambiguous causal clocks reject proof. Another ordinary Case's access to the
same key cannot provide a witness or invalidate this Case's proof, including
when its records are loaded later.
Source lifetime duration, including deletion, must remain below the positive TTL.

At runtime creation and deletion retain their ordinary finite matching. Within
that established lifetime, actual Target GETs return the current matched Target
SET bytes, including its own stable fields and timestamp representation. A
refresh SET requires a successfully delivered GET, preserves all other fields
and options, and validates each declared timestamp against its independent
request clock. It cannot create a missing key or borrow another lifetime's state.
Repeated reads may observe the same current value; refreshes may coalesce or
repeat. One successful read covers equivalent Source GETs in that lifetime;
one successful refresh covers equivalent Source refresh SETs. No read/refresh
witness means those Source observations remain unused. Content/list operations
and APPEND bytes retain their own obligations and are never consumed by this rule.

The runtime stages state at matching admission, as Redis executes SET before
its response is read. Every actual response remains in flight until transport
completion. Only successful delivery covers Source observations; any failed
delivery poisons the lifetime and keeps the Case dirty. A deletion cannot cross
pending activity I/O. Reads before creation and after deletion stay finite.
No infinite nil polling or retry-until-present behavior is introduced.

The permission is opt-in: absent declarations leave historical behavior unchanged.
Enabling it adds complete Source proof and explicit Target state checks; it is
not an unconditional promise that arbitrary historical policies/traces still
pass. Regression tests retain an ordinary finite trace and verify unchanged,
merged and split refresh rounds over real RESP TCP delivery.

Bounds are 128 keys, 4096 Source observations and 4096 Target calls per Case,
1024 lifetimes per key, 16 timestamp pointers and 1 MiB per value/response.
`redis.activity_refreshes` exposes at most 1000 transport-complete audits with
Source creation/witness references, covered counts, Target admission/observation
IDs and key/value fingerprints; omission counts are explicit. No JSON values or
stream bytes enter these audits. Runtime mismatches use the existing
`redis_state_observation_mismatch` diagnostic with the distinct activity rule ID.
