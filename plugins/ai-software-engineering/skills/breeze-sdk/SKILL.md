---
name: breeze-sdk
description: "Design, implement, integrate, migrate, or review business-independent remote-resource SDK clients used with Breeze. Use for Memcached, Redis, MySQL, Kafka, queues such as MCQ or QueueService, Motan, or other remote resources; keep business behavior in the owning backend capability."
---

# Breeze SDK

Build reusable consumer SDKs that turn logical remote-resource identities into
correctly registered Breeze listeners and long-lived application clients.
Preserve Java SDK compatibility without coupling business code to descriptor
filenames, caller-selected ports, or resource lifecycle.

The consumer path is:

```text
application composition root
  -> brz-<resource> package
  -> shared descriptor library
  -> Breeze listener
  -> remote resource
```

The project CLI is not part of this resource path.

## Ownership

Use this skill for business-independent remote-resource access whose identity,
discovery, listener, or connection lifecycle is managed through Breeze.
This explicitly includes Memcached, Redis, MySQL, Kafka, queues such as MCQ or
QueueService, and Motan. Treat Motan itself as business-independent platform
infrastructure, not as a capability-owned provider client. The set remains
open to new Breeze-managed resource types.

- logical resource identity and descriptor parsing;
- descriptor resolution and permitted registration through one generic policy;
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
2. Enumerate each resource's complete logical identity and select one
   descriptor policy: `RequireExisting`, `EnsurePresent`, or `CreateNew`.
   Do not put recording, replay, comparison, test, or deployment scenario
   names in Breeze SDK types or branches.
3. Read [descriptor-lifecycle.md](references/descriptor-lifecycle.md) and
   implement one shared, deterministic descriptor layer before resource
   clients. Keep policy-specific mutation authority explicit.
4. Read [resource-clients.md](references/resource-clients.md), classify the
   reusable resource layer separately from its business adapter, and implement
   only the needed resource packages. Construct long-lived clients in the
   composition root and keep business semantics in the owning capability.
5. Read [verification.md](references/verification.md), run focused checks for
   every affected mode and resource, then run repository-required gates.
6. Return exact resources, modes, changed behavior, checks, and blockers to the
   invoking workflow. Do not declare a rewrite, replay, or migration complete.

## Non-Negotiable Runtime Rules

- `RequireExisting`: reuse one exact descriptor; fail when it is absent.
- `EnsurePresent`: reuse one exact descriptor; register it when absent.
- `CreateNew`: fail when the exact descriptor exists; register it when absent.
- Every policy rejects malformed, duplicate, or conflicting claims. No policy
  may rewrite, rename, delete, replace, or renumber an existing descriptor.
- Registration must lock the shared directory, rescan under the lock, select
  an eligible random port, create the descriptor atomically, and wait with a
  bounded deadline for the Breeze listener.
- The application composition root supplies complete logical identities and
  generic Breeze settings. Each `brz-*` resource package calls the shared
  descriptor library and constructs its own long-lived client.
- A project CLI or runner may pass one generic descriptor policy and topology
  settings selected by its caller. It MUST NOT infer that policy by inspecting
  runner state, enumerate resources, invoke a descriptor resolver per resource,
  resolve ports, export descriptor-derived `host:port` values, or change when
  a resource is added.
- Treat the descriptor implementation as an internal SDK library. A diagnostic
  executable may inspect it manually, but normal application startup MUST NOT
  depend on a descriptor executable.
- Never parse replay sessions, dependency JSONL, recorded commands, keys, or
  target ports to infer resource identity or configuration.
- Never substitute a protocol-default port for missing Breeze evidence.
- Keep parsing independent of directory iteration order, bound all waits and
  operations, and do not log secrets.

## Result Contract

Report:

```text
resources, descriptor_policies, identity_source, descriptor_behavior,
changed_packages, application_wiring, checks, blockers
```

For any startup blocker, identify the missing or conflicting identity
evidence, the responsible owner, the acceptance check, and the safe resume
point. Let the invoking workflow determine the overall task status.
