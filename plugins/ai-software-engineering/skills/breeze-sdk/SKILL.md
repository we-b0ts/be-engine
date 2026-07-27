---
name: breeze-sdk
description: "Design, implement, integrate, migrate, or review Breeze SDK resource clients for MySQL, Redis, Memcached, Kafka, MCQ, and QueueService. Use for Breeze SDK development or any Breeze-backed integration with these resources."
---

# Breeze SDK

Build a reusable consumer SDK that turns a logical middleware resource identity
into a correctly registered Breeze listener and a long-lived application
client. Preserve Java SDK compatibility without coupling business code to
descriptor filenames or caller-selected ports.

## Ownership

Use this skill for Breeze-specific client and runtime behavior:

- logical resource identity and descriptor parsing;
- exact descriptor reuse and independent-startup registration;
- replay-safe, read-only descriptor resolution;
- `brz-*` package boundaries and application wiring; and
- Breeze-specific tests and compatibility evidence.

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
4. Read [resource-clients.md](references/resource-clients.md) and implement
   only the needed allowlisted packages. Construct long-lived clients in the
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
- Never substitute MySQL, Redis, Kafka, Memcached, or other protocol-default
  ports for missing Breeze evidence.
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

When blocked, identify the missing or conflicting identity evidence, the
responsible owner, the acceptance check, and the safe resume point.
