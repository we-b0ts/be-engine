# Redis absent read observations

An independent cancellation poll can issue different numbers of reads when
resource delivery or persistence takes longer during Replay. A count difference
does not establish a rule: verify the Source and Target lifecycle first.

For an explicitly proven absent-state lifetime, declare:

```yaml
redis:
  keys:
    'task:cancel:*': {read_observation: true}
```

The current capability supports single-key `DEL`/`UNLINK`, nil `GET` observations,
and a closing deletion. The initial successful deletion establishes absence;
it can delete zero or one existing value. Later deletions must preserve the
proven absent state. Historical reads before the first deletion remain finite.
Every selected key needs complete causal Source evidence. SET, expiry operations,
non-nil observations, multi-key access, foreign mutations, stateful connections
and transactional ownership reject the proof. Ordinary finite reads in another
Case neither establish this lifetime nor supply observations for it.

One successful Target observation can cover recorded nil reads in its current
epoch; additional reads can repeat that same witnessed nil response. The initial
deletion must finish delivery before permission begins. The closing deletion
ends permission, and an epoch without a Source GET cannot borrow a future or
previous observation. Both deletions remain finite required dependencies.
Missing all reads leaves dirty Source dependencies. Failed observation delivery
retains dirty evidence and prevents reuse. Endpoint, database, authentication,
protocol, Case and key remain checked. Existing bounds on calls, keys and
observations still apply.

This is distinct from finite `read_commutation`, whose extra reads still fail,
and identity `read_back`, which requires a successful owned SET. The declarations
cannot own the same read response together. Replace the applicable declaration
through normal `rule plan`/`rule apply`; do not add a fabricated identity SET.
An annotated plan must prove the independent polling loop and complete deletion
boundaries using Source file and line references. Source validation freezes the
recording evidence and requires a fresh genuine Target Replay; it cannot certify
Target behavior by itself.

Runtime rule reports use `kind: redis_read_observation`. Each delivered read
retains a Source observation, its establishing mutation, Target arrival index
and covered-Source count in the state-observation audit. No recording, request,
response or authored policy is modified automatically.
