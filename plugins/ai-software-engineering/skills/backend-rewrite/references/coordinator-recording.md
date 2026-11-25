# External Recording Evidence

Backend rewrite never starts recording, allocates capture IDs, owns recording
processes, or recovers their containers. Recording belongs to the independent
`traffic-e2e record` service and its deployment caller.

Place completed runs under the initialized Target's conventional
`.traffic-e2e/local/artifacts/recordings/<run-id>/`. Preserve the complete
immutable recording directory and its network manifest. Encrypted headers require
the matching private key at `.traffic-e2e/local/secrets/traffic-e2e-enc.sec`,
outside Target; preserve permissions and do not replace a conflicting key.
No import command is needed.

## Source Session

Current standalone recording captures concurrent ingress and dependencies on
one Source sequence from launch through exit. The recording caller selects the
ingress workload with recorder HTTP gateway rules. Recorder opens ingress at
readiness. Optional coordination Redis handles recorder discovery and ingress
reservations. On normal shutdown, Recorder closes admission, gives active
ingress up to 15 seconds to finish, and records an `engine_shutdown`
cancellation for any request still active before stopping Source. Keep the sealed
`dependency-manifest.json`, `events.tsv`, dependency indexes and payload tree
together. Source startup, background and teardown traffic stay on the shared
timeline.

Keep the recorded ingress paths verbatim, including trailing slashes and
repeated separators. An admitted response with status 404 is part of the
assertion evidence like any other recorded response.

Select the exact 14-digit run ID with `recording_run_id` in local
`.traffic-e2e/regression.yaml` or `session --recording-run-id <run-id>`. Use
`backend-rewrite --target-root <canonical-root> session run` to verify the
complete sealed session. If the recording is missing or capture is incomplete,
obtain a complete external recording. Use the same sealed input for Target
repair and capture a new session only when the Source workload or acquisition
needs to change. See [Source session regression](session-regression.md).

## Legacy Case Workflow

Apply the following adoption and refresh steps only to existing recordings with
published Cases when the coordinator is using `backend-rewrite next`.

Use the existing local `.traffic-e2e/regression.yaml` `recording_run_id` to select
an exact batch. Without a pin, next discovers an available completed batch and
then retains that identity. Missing or rejected evidence returns `input_required`
with the required directory and no recording execution command. Do not invent
traffic or edit recordings. Use the returned bounded `recording_input_diagnosis`
to identify rejected evidence. Run next after external evidence is available.

Failed focused Replay attempts reuse the adopted cases. Use the Source
Session entrypoint for new recordings.

After adoption, follow the combined repository analysis and normal coordinator actions.
Recording contents, old batch identities and verification history remain immutable.

Valid recorded HTTP paths retain their exact identity, including trailing slashes
and repeated separators. They remain usable recorded cases even when Source
returned 404 because no handler exists. Such responses are ordinary assertion
oracles, not recording failures. Exact route selectors and local regression
`only`/`skip` may name these paths verbatim; `/api/items/` never aliases
`/api/items`. Wildcard patterns retain their canonical separator grammar and
do not absorb noncanonical paths. Skip controls selected workflow coverage;
it does not alter recorded requests, expected responses or assertion policy.
Removing skip restores the original cases and their response checks.
