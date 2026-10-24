# Redis finite read commutation

An independent polling task can interleave a `GET` with delayed writes on a
pooled Redis connection. Requiring that incidental wire order can deadlock a
Target whose polling and flush tasks run at different speeds.

Declare `read_commutation: true` to permit selected, finite nil observations
to commute with unrelated commands:

```yaml
redis:
  keys:
    'task:cancel:*': {read_commutation: true}
```

The annotated plan supplies independent Source proof of the polling task,
complete nil responses and independence from delayed writes. Runtime rendering
omits proof. Key patterns have no resource or database selectors; actual
Source/Target endpoint, database, authentication and protocol remain exact.

The native planner and Replay share complete Source validation for each
selected Case/key. All selected GET responses must be RESP nil bulk values.
Same-key `DEL` is allowed only with its original zero response and stays an
ordinary finite, ordered command. Mutations, non-nil responses, multi-key
observations, ambiguous script key access, foreign Case/Global overlap and
stateful or transactional read connections reject the proof. Late overlapping
inventory cannot extend an installed permission. No partial permission is
installed when any selected key fails validation.

Only proven GET exchanges leave the ordinary connection-order barrier. Their
endpoint, database, user, Case, key/arguments, recorded response, connection
eligibility, single claim and successful delivery remain checked. Other
commands keep their original lane order, APPEND byte fences and TTL checks.
Rules own the unchanged read response and cannot overlap another response
delivery owner.

This effect does not make polling optional or reusable. Extra Target reads
still fail; missing reads remain unused Source dependencies; failed delivery
remains dirty. A finite-count difference after the ordering deadlock is fixed
needs its own evidence and decision. In particular, a recorded cancellation
transition must never be replaced by an always-false observation.

Use the ordinary `backend-rewrite rule plan --file ... --evidence ...` and
`rule apply --plan <plan-id>` transaction. Source self-validation authorizes a fresh
Replay obligation, never a successful Target result. Runtime dependency-rule
reports include `kind: redis_read_commutation` and actual successful use counts;
individual matches retain their original Source sequence and Target arrival
index.
