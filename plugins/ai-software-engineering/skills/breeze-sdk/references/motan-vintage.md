# Motan and Vintage Development

Implement Motan and Vintage as reusable platform libraries when the source
service depends on them. Do not replace them with fixed endpoints, a generic
round-robin client, or capability-local shortcuts.

## Source of Truth

Use the source service's configuration and pinned versions as the baseline.
Inspect [motan-weibo](https://git.intra.demo.test/openapi_rd/motan-weibo) for
integration, the [Vintage Java SDK](https://git.intra.demo.test/platform/vintage/-/tree/vintage-1.2.18)
for its current dependency, and matching Motan source. The Vintage repository's
default branch is the Go server; for another service, open its pinned Java tag.

Use these source areas as navigation, adjusting paths for the pinned version:

- `motan-weibo-registry-vintage`: Motan/Vintage integration, identity mapping,
  subscriptions, commands, and excision selection;
- Vintage `NamingServiceClient`, `NamingServerProxy`,
  `DataRepositoryFactory`, `SnapshotProcessor`, and `NodeExciseStrategy`:
  discovery, updates, cache, snapshot, fallback, and node retention;
- Motan `ClusterSupport`, load balancers, HA strategies, transport client, and
  heartbeat manager: full node-set updates, routing, retries, fusing, and
  recovery; and
- source service configuration: the behavior actually enabled for this
  service, including method-level overrides and runtime switches.

## Required Boundaries

Keep Motan and Vintage as separate sibling libraries under the Breeze package
root. Let Motan depend on Vintage:

```text
breeze/
  motan/
  vintage/
```

Vintage owns reusable discovery, node state, subscription, snapshot generation
and loading, and excision behavior. Motan owns protocol, transport, referers,
cluster routing, load balancing, failover, fusing, recovery, and shutdown.
Keep RPC service interfaces, DTOs, method semantics, application errors, and
business fallback decisions in the capability adapter.

## Do Not Miss

Trace and preserve all behavior relevant to the active source service:

- logical group/service, cluster, node type, protocol, version, serialization,
  Vintage endpoint, snapshot directory, and compatible configuration loading;
- initial Vintage lookup, sign-based update detection, subscriptions, node
  status parsing, and complete node-set refreshes;
- Vintage itself generates and updates snapshots from validated discovery
  results; do not delegate this to business code or a CLI;
- the snapshot directory hierarchy, filename derivation, encoding, payload
  format, load order, persistence, and disaster fallback remain compatible
  with the source Vintage version;
- Vintage static, dynamic, or ratio excision behavior and its minimum-node
  protection;
- atomic application of full discovery updates, malformed-node isolation,
  referer reuse, and removal without connection leaks;
- Motan's protection against an empty discovery update erasing the last usable
  referer set;
- source-configured load balancing, method/service timeout and retry
  precedence, transport failover, and business-exception handling;
- consecutive-failure fusing, removal from normal selection, heartbeat
  probing, and successful recovery into the selectable set; and
- bounded deadlines, attempt counts, queues, background work, and orderly
  shutdown.

Inspect source code for the exact algorithms, thresholds, rounding, constants,
status transitions, and error classification. Preserve their observable
semantics without copying accidental nondeterminism or unsafe resource
management.

Implement backup requests, adaptive weighting, command-driven routing, or other
optional extensions only when source configuration shows active use.

## Completion Checks

Before returning the implementation, prove with focused tests that:

- source configuration produces the compatible Vintage identity and lookup;
- live discovery makes Vintage write a source-compatible snapshot; existing
  source snapshots load, and generated snapshots load again after restart;
- initial discovery, a valid update, a malformed update, remote unavailability,
  and snapshot fallback preserve the expected last valid node set;
- configured excision and minimum-node protection cannot accidentally drain
  the cluster;
- a full node update swaps safely and retires removed referers;
- transport failures switch nodes and eventually fuse the failing endpoint,
  while a successful probe restores it;
- retry and timeout behavior follows source method/service configuration and
  does not retry business exceptions; and
- optional strategies remain disabled unless enabled by source evidence.
