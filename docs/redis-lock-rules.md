# Redis lock token rules

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v2` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


A source-proven `redis.lock` dependency rule permits different randomly generated
ownership tokens while preserving their recorded equality and uniqueness within
one case, endpoint, database, authenticated username and actual key. It does not
interpret Lua, emulate Redis locking, or synthesize success/failure responses.
Genuine target Redis clients still consume finite recorded exchanges.

## Configuration

Add a rule to `.traffic-e2e/verification.yaml` through the coordinator's plan/apply
commands. The complete rule shape is:

```yaml
dependency_rules:
  - id: order-lock
    protocol: redis
    target:
      host: redis.example.internal
      port: 6379
    redis:
      lock:
        key:
          prefix: 'lock:order:'
        source_evidence: 'LockStore:acquire/release generates an ownership nonce and conditionally deletes by that nonce'
```

Host, nonzero port, bounded key selector and source evidence are required.
Keys may use an exact string, prefix/suffix selector, or numeric selector such as
`{prefix: 'lock:order:', numeric: true}`. Selectors choose recordings; they never
translate actual keys. No application-specific prefix, UUID format, Lua script,
SHA, or argument position is built into the rule.

Supported command shapes are:

- `SET key token NX EX/PX ttl`, including expiry-before-NX option order.
- `EVAL script 1 key token` and `EVALSHA sha 1 key token`.
- `DELEX key IFEQ token`, available in Redis 8.4 and later.

Tokens are opaque nonempty values of at most 1024 bytes. Source token equality
identifies references to preceding SET requests in the same case and Redis
session identity. First matching SET establishes a source-to-target token
binding. Repeated occurrences must use the same target token; distinct source
tokens cannot collapse into one target token for the same resource. This also
preserves acquisition retries and finite NOSCRIPT/script-load/retry exchanges.
The rule does not assume that a SET succeeded or infer ownership from a response.

Every other argument remains exact, including key, TTL, NX/expiry options,
script body/SHA and key count. RESP version, database, authentication, target
endpoint, case boundaries, stateful connection claims, source lane order,
recorded outcomes and finite consumption remain enforced. Global dependencies
are not normalized. Unrelated script arguments and unsupported multi-key,
renewal, hash-based/reentrant lock protocols remain exact.

Lock ownership is correlated by the token and resource identity, independently
of the physical socket. A lane containing ordinary SET, GET/MGET and EVAL/EVALSHA
calls can replay in recorded order across multiple target connections, including
script-cache misses, SCRIPT LOAD and retries. Retained session operations,
transactions, subscriptions, blocking operations and SCRIPT DEBUG still bind
the whole lane to one target connection; a lock rule does not waive them.

A changed script does not invalidate this key-scoped rule, but an actual script
identity difference from the immutable recording still requires refreshed
recordings. Failed release, contention and expiry behavior must remain genuine
target behavior; this rule does not dynamically compute Lua results or certify
concurrency semantics.

## Discovery and authoring

During an unmatched target request, Replay captures a candidate only if all
non-token arguments and session/endpoint/case scope match and the tokens differ.
A script or conditional-delete candidate must reference a preceding source SET
nonce. Reports retain exchange and target-token fingerprints, never token bytes.
Once a rule covers an exchange, a wrong target token remains a target mismatch;
it does not generate another rule candidate.

The current `dirty_clusters` query returns `facts.redis_lock_candidates`.
With candidates, it advertises `rule_hints` and an `applicable_rule_planners`
entry for `redis_lock`, including the current evidence ID and help command.
Hints can appear for response, dependency or Replay issues before responses pass.
They are mechanical candidates, not proof that the key is a lock or the script
performs conditional deletion. Trace source/client acquisition and release and
return exact selector plus source file/symbol proof to the coordinator.

```text
backend-rewrite dependency-rule plan redis lock \
  --evidence-id <current-dirty-evidence> \
  --rule-id order-lock \
  --host redis.example.internal --port 6379 \
  --key-prefix lock:order: \
  --source-evidence 'LockStore:acquire/release uses random ownership nonces and compare-delete'
backend-rewrite dependency-rule apply <returned-plan-id>
```

`--key`, `--key-prefix`/`--key-suffix`, and `--numeric-key-pattern` use the same
selector conventions as other Redis value rules. No ownership flag or separate
release rule is required; this preserves request ownership.

Planning verifies a finalized Replay witness against a completed standard
recording and requires a same-case acquisition/reference pair. It returns a
reviewable policy diff. Apply checks policy and recording/report revisions,
rejects stale evidence, preserves unrelated policy, and reuses identical rules.
Overlapping lock selectors or lock/unordered selectors for the same endpoint
are rejected. Apply requires fresh Replay; it never reclassifies old failures,
changes recordings, omits calls or completes the API offline.

Reports from older engines lack token witnesses. They return
`requires_fresh_replay: true` and require a fresh Replay with this engine before
planning; no new recording is needed merely to add these witnesses.

Redis's [distributed-lock pattern](https://redis.io/docs/latest/develop/clients/patterns/distributed-locks/)
describes why the nonce's identity is dynamic while its equality matters.
