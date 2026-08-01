# Dirty Dependency Diagnosis

Use only when `gates.responses=passed`, `gates.replay=complete`, and
`gates.dependencies=dirty`. The finalized report then contains unmatched,
unsupported, unsafe, unused-case, proxy-error, or other dependency coverage
findings. A dependency gate of `unknown` belongs to replay evidence repair, not
this workflow.

## Next Action

1. Group dirty entries by protocol, target, command or operation, and key,
   route, or request shape. Preserve representative case IDs and counts.
2. Read the immutable case dependency records for the exact report entries;
   do not infer ownership from the aggregate summary alone.
3. Trace the source caller and classify the traffic by causality:
   - request-owned and required: repair target behavior or replay support;
   - process-owned and response-driving: use a supported `runtime_state` rule;
   - process-owned and response-independent: use a supported `independent`
     rule;
   - unresolved: retain it as case-owned dirty evidence.
4. For a supported background rule, run the evidence-validating
   `config recorder plan background-dependencies` command, inspect its selector
   and matched case IDs, then run the same command with `apply`.
5. Create a new standard recording after any recorder rule change and rerun
   replay. Never edit, trim, or reclassify the old recording.

## Guardrails

- Diagnose response mismatches first. Unrelated dirty traffic must not preempt
  response repair.
- Timing overlap, high volume, scheduler-like names, unused exchanges, or a
  passing response do not prove background ownership.
- Background rules are process-level. Prove the response relationship from
  source causality; never persist an API selector on the rule.
- Match the narrow stable service identity and operation shape. Do not persist
  source-process values, remote responses, dynamic endpoints, or diagnostic
  aliases.
- If no source-proven safe rule or replay repair exists after responses pass,
  return `incomplete` with the concrete dirty category, owner, next TODO, and
  acceptance check.

## Protocol Routing

### HTTP

For dirty HTTP exchanges, group by normalized authority, method, and path.
Use the supported HTTP `independent` rule only when source proves all of these:

- startup, lifecycle, scheduler, or permanent-worker code owns the trigger;
- request context, API parameters, and API-scoped state do not control it;
- the selected API does not await, start, stop, or consume its result; and
- the selected API response and required side effects do not depend on it.

Then match the exact authority, method, and path prefix. If any fact is unclear
or the request is request-owned, retain it as case-owned dirty evidence or
repair target/replay behavior. Record only the source revision and bounded
file/symbol ownership explanation, never query values, credentials, headers,
or bodies. Use host-wide `allowed_unused_http_hosts` only as a compatibility
exception when an immutable older recording cannot be replaced and source
proves the entire host is unrelated.

### Memcached

For dirty Memcached exchanges, first determine whether scheduled `get`
requests populate response-driving local state. The supported background rule
is Breeze-backed `runtime_state`: match the stable Breeze identity, exact
`get`, bounded numeric key series, and initial-load timeout. If the traffic is
response-independent or does not fit that shape, retain it as dirty evidence
or a capability gap rather than forcing it into the current rule.

### Redis

For the supported Redis independent rule, use `protocol=redis`, a source-proven
port set, exact `ZCOUNT`, and exact key prefix and suffix. One logical service
may own multiple stable ports. Do not persist Redis domains: operational DNS
names may change while the service ports remain stable. Domain observations may
be reported for diagnosis but never participate in rule matching. One case may
observe only a subset of the configured ports. Add newly source-proven group
ports through `plan|apply`; do not remove existing ports or change the command
or key shape under the same rule name.

### Motan

For dirty Motan exchanges, use the supported `independent` rule only when
source causality proves process ownership and response independence. Match the
exact Vintage group, Motan interface, and method; derive the Vintage cluster as
`<interface>/service`. Do not persist endpoints, Vintage aliases, or payloads.
Asynchronous, scheduled, or repeated execution alone is insufficient: when
business behavior awaits or consumes the result, repair the normal Motan or
Vintage initialization, refresh, and call path instead of classifying it as
background traffic.
