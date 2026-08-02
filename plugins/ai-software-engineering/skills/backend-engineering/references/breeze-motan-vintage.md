# Breeze Motan And Vintage Compatibility

Use this reference when the source service depends on Motan or Vintage. Do not
replace either with fixed endpoints, a generic round-robin client, or a
capability-local shortcut.

## Source And Ownership

Use the source service's configuration and pinned Motan, motan-weibo, and
Vintage versions as the authority. Inspect the matching source integration,
not an unpinned default branch or a version copied from another service.

Keep Motan and Vintage as sibling Breeze libraries and let Motan depend on
Vintage. Vintage owns reusable discovery, subscriptions, node state, complete
node-set updates, snapshots, fallback, and node excision. Motan owns protocol,
transport, referers, codec integration, routing, load balancing, failover,
fusing, recovery, and shutdown. The capability owns the remote service
interface, DTOs, method semantics, application errors, and business fallback.

## Compatibility Contract

Trace and preserve only behavior enabled by the active source service,
including:

- logical service identity, cluster, node type, protocol, version,
  serialization, Vintage endpoint, and compatible configuration loading;
- initial lookup, sign-based update detection, subscriptions, node parsing,
  and atomic complete-node-set refresh;
- source-compatible snapshot hierarchy, naming, encoding, payload, load order,
  persistence, restart behavior, and disaster fallback;
- configured static, dynamic, or ratio excision and minimum-node protection;
- referer reuse and safe retirement without connection leaks;
- protection against an empty or malformed discovery update erasing the last
  valid node set;
- source-configured method/service timeout and retry precedence, transport
  failover, and business-exception classification; and
- consecutive-failure fusing, heartbeat probing, and successful recovery into
  the selectable set.

Inspect the pinned source for exact algorithms, thresholds, rounding,
constants, state transitions, and error classification. Implement backup
requests, adaptive weighting, command routing, or other optional strategies
only when source configuration proves they are active.

## Acceptance

Focused tests must prove compatible identity and lookup, live snapshot writing
and restart loading, valid and malformed node updates, remote-unavailable
fallback, configured excision and minimum-node protection, safe full-node-set
replacement, transport failover and recovery, and method/service timeout and
retry precedence. Confirm optional strategies remain disabled without source
evidence.
