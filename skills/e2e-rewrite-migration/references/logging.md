# Logging And Diagnostics

Read this reference only for a runnable service, worker, or scheduled job when
existing diagnostics are insufficient or changed by the current migration.

## Required Outcomes

The final target must make these questions answerable without exposing secrets:

- did normal startup load the intended config and reach readiness or bind?;
- did the selected request or job enter the migrated capability?;
- which dependency boundary failed and what was the root cause?;
- was the failure in target behavior, replay setup, recording evidence, config,
  or an external environment?;
- where can the user find the relevant diagnostic output?

Reuse existing structured logs, traces, platform stdout collection, or test
artifact conventions. Do not add a parallel logging subsystem merely to satisfy
the skill.

## Minimum Events

For the migrated scope, preserve or add:

- startup and shutdown with config source and listener or job identity;
- one request or job completion event with route or scope, result, and latency;
- dependency-boundary failures with operation, redacted target, latency, and
  root cause;
- actionable config, decode, replay-routing, and unhandled errors.

Include request or correlation ids and recorded case ids when already available
or inexpensive to propagate. Keep categories queryable, but do not require
separate physical files.

## Safety

Do not log credentials, authorization headers, cookies, tokens, private keys,
full DSNs, full SQL binds, or full request and response bodies by default. Use
redacted dependency identities and bounded error context.

## Local Commands

Commands that start background processes must expose their pid or health state,
diagnostic location, and an idempotent cleanup path. On E2E failure, point to the
smallest relevant log or trace excerpt rather than dumping all output.

Put skill-owned local logs, PIDs, discovered addresses, and temporary diagnostic
files under `.traffic-e2e/local/<run-key>/logs/` or `tmp/`. Do not relocate logs
owned by an existing target logging system merely to satisfy this convention,
and never stage or commit the local copies.

Do not require file rotation, retention, cleanup jobs, four dedicated log files,
or a new `doctor` command unless the target already uses those conventions or
the user explicitly requests production observability work.

## Completion Rule

Recorded E2E response compatibility is insufficient when a runnable target
cannot expose the root cause of a startup, request, or dependency failure. The
diagnostics requirement is satisfied by an existing equivalent system; record
the command or path used to inspect it rather than creating duplicate tooling.
