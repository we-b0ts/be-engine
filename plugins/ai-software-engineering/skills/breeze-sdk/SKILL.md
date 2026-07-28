---
name: breeze-sdk
description: "Design, implement, integrate, migrate, or review business-independent remote-resource SDK clients used with Breeze. Use for Memcached, Redis, MySQL, Kafka, queues such as MCQ or QueueService, Motan, or other remote resources; keep business behavior in the owning backend capability."
---

# Breeze SDK

Build reusable consumer SDKs that turn logical remote-resource identities into
correctly registered Breeze listeners and long-lived application clients.
Preserve Java SDK compatibility without coupling business code to descriptor
filenames, caller-selected ports, or resource lifecycle.

## Ownership

Use this skill for business-independent remote-resource access whose identity,
discovery, listener, or connection lifecycle is managed through Breeze.
This explicitly includes Memcached, Redis, MySQL, Kafka, queues such as MCQ or
QueueService, and Motan. Treat Motan itself as business-independent platform
infrastructure, not as a capability-owned provider client. The set remains
open to new Breeze-managed resource types.

- logical resource identity and descriptor parsing;
- exact descriptor reuse and independent-startup registration;
- replay-safe, read-only descriptor resolution;
- reusable client, pool, producer, consumer, channel, or transport lifecycle;
- `brz-*` package boundaries and application wiring; and
- Breeze-specific tests and compatibility evidence.

Classify by ownership, not by class name or protocol. Logging, serialization,
authentication, metrics, and ordinary provider SDKs do not belong here merely
because they are reusable. A remote-service client belongs only to the extent
that it provides reusable Breeze-managed resource access.

Keep every business contract outside this skill: SQL and tables, cache keys and
cache policy, queue topics and message schemas, RPC service interfaces and
method semantics, provider request/response mapping, fallback decisions, and
cross-resource orchestration. Put those concerns in a capability-owned adapter
that depends on the narrow Breeze SDK client. This boundary applies even when
the business behavior is currently simple; complexity is not the ownership
test. For Motan, this exclusion applies to the invoked business service
contract, not to the Motan SDK or protocol implementation.

Use the [`backend-engineering` skill](../backend-engineering/SKILL.md) for
general code quality. The invoking workflow retains scope, sequencing,
evidence gates, and delivery. The
[`traffic-e2e` skill](../traffic-e2e/SKILL.md) owns recording and replay
operations; the
[`platform-recording-init` skill](../platform-recording-init/SKILL.md) owns the
source recording topology, shared mounts, and source-image patch.

Do not operate or modify the Breeze server, copy SDK rules into application
`AGENTS.md`, or make each consuming repository the permanent owner of the SDK.
A service-local implementation is transitional when a standalone Breeze SDK
project or dependency is available.

## Required Workflow

1. Inspect the source Java SDK behavior, existing descriptors, target
   composition root, dependency configuration, and applicable repository
   instructions. Do not infer resource identity from a package name or
   protocol default.
2. Enumerate each resource's complete logical identity and required mode:
   `independent`, `recording`, `comparison`, or `replay`.
3. Read [descriptor-lifecycle.md](references/descriptor-lifecycle.md) and
   implement one shared, deterministic descriptor layer before resource
   clients. Keep mode-specific mutation authority explicit.
4. Read [resource-clients.md](references/resource-clients.md), classify the
   reusable resource layer separately from its business adapter, and implement
   only the needed resource packages. Construct long-lived clients in the
   composition root and keep business semantics in the owning capability.
5. Read [verification.md](references/verification.md), run focused checks for
   every affected mode and resource, then run repository-required gates.
6. Return exact resources, modes, changed behavior, checks, and blockers to the
   invoking workflow. Do not declare a rewrite, replay, or migration complete.

## Non-Negotiable Runtime Rules

- Match the complete resource identity and require exactly one compatible
  descriptor before using a port.
- During independent startup only, a missing descriptor may be created under
  the shared lock after a rescan, using an eligible random port and atomic
  creation, followed by bounded listener readiness.
- During replay, descriptors are immutable prerequisites. Never create,
  rewrite, rename, delete, or replace one; fail startup when the exact
  recording-time descriptor is absent or invalid.
- Never substitute a protocol-default port for missing Breeze evidence.
- Comparison source and candidate share one Breeze instance, socks directory,
  resource identity, and selected port.
- Keep parsing independent of directory iteration order, bound all waits and
  operations, and do not log secrets.

## Result Contract

Report:

```text
resources, modes, identity_source, descriptor_behavior,
changed_packages, application_wiring, checks, blockers
```

For any startup blocker, identify the missing or conflicting identity
evidence, the responsible owner, the acceptance check, and the safe resume
point. Let the invoking workflow determine the overall task status.
