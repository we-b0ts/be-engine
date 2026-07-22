# Backend Rewrite And Migration

Rewrite observable behavior and operational contracts, not source syntax. A
cross-language or architectural migration must preserve responses, dependency
roles, side effects, ordering, error semantics, metrics, configuration sources,
and lifecycle behavior unless the user approves a change.

## Discovery

Inspect the source route, job, or worker wiring; normal startup; authoritative
configuration; genuine dependency clients; schemas; side effects; diagnostics;
and representative tests or traffic. Treat source structure as evidence, not a
target architecture template.

Do not infer runtime configuration from downstream requests. Values loaded by
the source from a database, cache, configuration service, secret service, or
other dependency must continue through a genuine dependency path. Direct
startup inputs may move to an equivalent target configuration path when their
provenance is established.

## Incremental Delivery

Migrate one coherent capability or route group at a time. Keep the target
normally runnable and use production adapters rather than recording-backed,
fixture-backed, or test-only substitutes. Add focused tests for new local logic
without duplicating the complete source implementation in the test.

After behavior first passes, review names, ownership, visibility, dependency
direction, runtime/test separation, and resource behavior. Refactor only the
boundary introduced or expanded by the migration, then rerun affected evidence.

When recorded cases are the behavior contract, use the companion `traffic-e2e`
skill for recording, grouping, replay, dependency coverage, response
assertions, and completion evidence. Passing one response does not waive
missing side effects, dirty dependencies, startup differences, or incomplete
case coverage.

## Reusable Memory

Record a repository lesson only after a verified fix applies across multiple
capabilities or migration scopes. Keep the trigger, ineffective action to
avoid, and verified resolution concise. Do not copy transient logs, case IDs,
absolute local paths, secrets, or generated run state into prose.
