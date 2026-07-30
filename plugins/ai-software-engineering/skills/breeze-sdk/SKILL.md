---
name: breeze-sdk
description: "Design, implement, integrate, migrate, or review shared Rust platform libraries under Breeze. Use for platform logging, TAuth2 authentication, Motan, Vintage service discovery, Memcached, Redis, MySQL, Kafka, queues such as MCQ or QueueService, and other reusable platform capabilities; keep business behavior in the owning backend capability."
---

# Breeze SDK

Build the shared Rust platform library collection under Breeze. It includes
platform foundations such as logging and authentication as well as reusable
remote-resource SDKs. Preserve established platform contracts without coupling
business code to platform implementation details.

For descriptor-backed resources, the consumer path is:

```text
application composition root
  -> brz-<resource> package
  -> shared descriptor library
  -> Breeze listener
  -> remote resource
```

The project CLI is not part of this resource path.

## Ownership

Use this skill for platform-wide reusable libraries owned under Breeze,
including both platform foundations and business-independent remote-resource
access. This explicitly includes logging, TAuth2 authentication, Motan,
Vintage service discovery, Memcached, Redis, MySQL, Kafka, and queues such as
MCQ or QueueService. Treat these as platform infrastructure, not as
capability-owned implementations. The set remains open to new platform
capabilities.

- shared logging and observability foundations;
- shared authentication and discovery lifecycles;
- logical resource identity and descriptor parsing;
- descriptor resolution and permitted registration through one generic policy;
- reusable client, pool, producer, consumer, channel, or transport lifecycle;
- `brz-*` package boundaries and application wiring; and
- Breeze-specific tests and compatibility evidence.

Classify by platform ownership, not by class name or protocol. Logging and
TAuth2 are explicit platform-owned packages. Serialization, metrics,
authentication, and ordinary provider SDKs do not belong merely because they
are reusable; include them only when Breeze owns a platform-wide contract.

Keep every Breeze-owned package under one Breeze package root, using
`breeze/<package>` or the workspace-equivalent `crates/breeze/<package>`.
Do not place Breeze-owned packages at unrelated top-level paths.

Keep every business contract outside this skill: SQL and tables, cache keys and
cache policy, queue topics and message schemas, RPC service interfaces and
method semantics, authorization policy and whitelists, provider
request/response mapping, fallback decisions, and cross-resource orchestration.
Put those concerns in a capability-owned adapter that depends on the narrow
Breeze SDK client. This boundary applies even when the business behavior is
currently simple; complexity is not the ownership test. For Motan, this
exclusion applies to the invoked business service contract, not to the Motan
SDK or protocol implementation.

If it is not already active, read and use the
[`backend-engineering` skill](../backend-engineering/SKILL.md) for general code
quality. The invoking workflow retains scope, sequencing, evidence gates, and
delivery. The
[`traffic-e2e` skill](../traffic-e2e/SKILL.md) owns recording and replay
operations; the
[`platform-recording-init` skill](../platform-recording-init/SKILL.md) owns the
source recording topology, shared mounts, and source-image patch.

Do not operate or modify the Breeze server, copy SDK rules into application
`AGENTS.md`, or make each consuming repository the permanent owner of the SDK.
A service-local implementation is transitional when a standalone Breeze SDK
project or dependency is available.

## Required Workflow

1. Inspect the authoritative source SDK behavior and pinned implementation,
   target composition root, dependency configuration, applicable repository
   instructions, and existing descriptors when relevant. Inspect Java
   artifacts when they are the applicable source evidence. Do not infer
   resource identity from a package name or protocol default.
2. For each descriptor-backed resource, enumerate its complete logical
   identity and select one descriptor policy: `RequireExisting`,
   `EnsurePresent`, or `CreateNew`. Do not put recording, replay, comparison,
   test, or deployment scenario names in Breeze SDK types or branches.
3. For descriptor-backed resources, read
   [descriptor-lifecycle.md](references/descriptor-lifecycle.md) and implement
   one shared, deterministic descriptor layer before resource clients. Keep
   policy-specific mutation authority explicit.
4. For logging or TAuth2 work, read
   [platform-foundations.md](references/platform-foundations.md), implement
   only the needed foundation, and initialize it in the composition root.
5. For a remote-resource package, read
   [resource-packages.md](references/resource-packages.md), separate the
   reusable resource lifecycle from its business adapter, and construct the
   long-lived client in the composition root.
6. For Motan or Vintage work, also read
   [motan-vintage.md](references/motan-vintage.md) and preserve the source
   service's pinned discovery, failover, node protection, and snapshot
   semantics.
7. For remote-resource work, read
   [verification.md](references/verification.md). Run the checks selected by
   each applicable reference, then run repository-required gates.
8. Return exact packages, modes, changed behavior, checks, and blockers to the
   invoking workflow. Do not declare a rewrite, replay, or migration complete.

## Result Contract

Report:

```text
packages, platform_contracts, lifecycle, application_wiring, checks, blockers
```

For descriptor-backed packages, also report `descriptor_policies`,
`identity_source`, and `descriptor_behavior`. For any startup blocker, identify
the missing or conflicting platform evidence, the responsible owner, the
acceptance check, and the safe resume point. Let the invoking workflow
determine the overall task status.
