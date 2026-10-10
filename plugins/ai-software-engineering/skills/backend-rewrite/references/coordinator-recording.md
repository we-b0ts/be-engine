# External Recording Evidence

Backend rewrite never starts recording, allocates capture IDs, owns recording
processes, or recovers their containers. Recording belongs to the independent
`traffic-e2e record` service and its deployment caller.

Place completed standard runs under the initialized target's conventional
`.traffic-e2e/local/artifacts/recordings/<run-id>/`. Preserve the complete immutable
run, semantic dependencies and network manifest. Encrypted headers require
the matching private key at `.traffic-e2e/local/secrets/traffic-e2e-enc.sec`,
outside Target; preserve permissions and do not replace a conflicting key.
No import command is needed.

Use the existing local `.traffic-e2e/regression.yaml` `recording_run_id` to select
an exact batch. Without a pin, next discovers an available completed batch and
then retains that identity. Missing or rejected evidence returns `input_required`
with the required directory and no recording execution command. Do not invent
traffic or edit recordings. Use the returned bounded `recording_input_diagnosis`
to identify rejected evidence. Run next after external evidence is available.

Failed focused Replay attempts reuse the adopted cases. Capture-policy or Source
changes invalidate affected evidence and require a newer externally produced
batch; runs already present when refresh begins cannot satisfy this requirement.
The coordinator does not produce it. Applied capture rules accumulate
through the existing parked-API refresh lifecycle. Continue other runnable work;
when refresh is required, arrange external recording with the new policy.

After adoption, follow case-pattern identification and normal coordinator actions.
Recording contents, old batch identities and verification history remain immutable.
