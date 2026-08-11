# Recording Lifecycle

Read this guide only for `recording_required`, `recording_in_progress`,
`comparison_recording_required`, an explicit fresh-standard-recording request,
or a consolidated capture refresh. The main orchestrator owns every command in
this guide.

## Contents

- Execute and monitor recording actions
- Preserve or replace standard cases
- Request fresh standard traffic
- Consolidate capture refreshes

## Execute A Recording Action

This section applies to both standard and comparison recordings. For comparison
recording, do not infer permission to request or replace standard traffic.

Execute the exact opaque `action.commands.execute` argv with the named required
environment variables. The returned argv already binds the canonical absolute
`--target-root`; use its `cwd` unchanged. The command starts a detached
recording executor and returns immediately. Poll only the status command
returned by that execution. While recording is live,
`recording_in_progress.action.commands.status` remains the only polling command.

Run `action.commands.advance` only after `advance_required`. The allocated
identity is `action.details.run_id`; the coordinator owns its input mode,
lifecycle, and exact finalized manifest. Never select a recording by recency or
add manual curl, Replay, shell pipelines, backgrounding, or driver flags.

Duration and case limit belong to the preceding recording request and are bound
into the action ID. For explicit API selectors, duration is an upper bound and
the managed runtime may finalize after every selected API reaches its case
limit. With an omitted selector, retain the full duration so low-frequency APIs
remain discoverable. An empty run-local selector is intentional when the
workflow started without `--api`; recorder configuration admits traffic and
the finalized cases produce the stable inventory.

## Preserve Standard Cases

Ordinary repair keeps the finalized standard cases immutable. A failed focused
E2E attempt changes the target and reuses those cases. After focused E2E passes,
the coordinator allocates fresh comparison evidence without replacing the
standard cases.

After the first focused attempt, `next` and `status` include
`latest_focused_e2e`. `execution_mode=fresh_standard_cases` identifies the
first attempt against the current standard baseline;
`execution_mode=reused_standard_cases` proves reuse. The result also carries
the recording run ID, exact case source, optional case inventory ID,
previous/current attempt numbers, and pass status. It describes the latest
completed attempt; a later `next` without a target change does not imply that
another attempt ran.

Applying or confirming a source-proven process-owned dependency rule does not
authorize fresh traffic. The coordinator reclassifies the immutable focused
Replay evidence and returns its next action. Follow
[coordinator-evidence-actions.md](coordinator-evidence-actions.md) for that
mutation.

## Request Fresh Standard Traffic

Use `backend-rewrite recording request --kind standard` only for:

- an explicit caller request;
- a changed Recorder contract; or
- a changed source baseline.

Supply the corresponding reason and positive `--duration-seconds` and
`--per-api-case-limit` values. Omit `--api` to replace a narrowed scope with
every API admitted by recorder configuration. Provide `--api` only for an
explicitly single-API recording.

An identical pending request is idempotent. A different pending request
requires explicit `--replace-pending`. The coordinator preserves prior
artifacts, clears state derived from the old baseline, allocates a new run, and
returns `recording_required`; execute that action and resume with `next`.

Historical recording input is reusable only when its complete selector exactly
matches the requested selector. Omitted selectors match only omitted selectors;
a single API matches only that exact API. Never split or merge recordings
because boot and case evidence belong to one recording lifecycle.

When no exact atomic input exists,
`action.details.input_mode=external_live_traffic` opens a fresh recording
window. Treat its bounded recent candidate scopes and rejection counts in
`action.details.recording_input_diagnosis` as complete. Do not inspect internal
state or invent traffic.

## Consolidated Capture Refresh

A recorder-capture apply is coordinator-owned and is the exception to the
explicit request rules: never follow it with `recording request`. Apply returns
either another runnable API command or, after runnable inventory drains, the
exact consolidated recording command. Multiple applied capture rules
accumulate before that one full-scope recording.

`awaiting_recording_refresh` means an API has an applied, source-proven capture
rule but cannot be reverified against the old baseline. It is parked, not
complete or blocked. Continue pending APIs and existing workers; other APIs may
still compare against the current baseline. When no runnable item remains, the
coordinator atomically returns one `recording_required` refresh.

The new finalized recording replaces the shared baseline atomically and
invalidates old Replay/comparison evidence. It never creates per-API recording
generations.

After a system repair, do not choose fresh traffic yourself. The
coordinator-issued repair verification decides whether to allocate fresh
standard cases or replay the existing cases. Follow
[recovery-and-system-repair.md](recovery-and-system-repair.md).
