# Standalone Source Recording

Use the single `traffic-e2e record` command inside the prepared Source environment:

```bash
traffic-e2e record --config /etc/traffic-e2e/project.yaml \
  --source-workdir /app --data-root /data/traffic-e2e \
  -- <source-command> [args...]
```

Project configuration is optional. Preserve configured HTTP include/exclude
rules; their default admits all methods and paths. Ingress selects API traffic.
There is no per-run API selector. Source runs as 998:998; the controller owns
interception, trust, readiness, shutdown and finalization.

## Deployment

The project owns `.traffic-e2e/Dockerfile.recording`. Build it from the real Source image, install
the engine and its interception tools (`setpriv`, `iptables`, `ip`, and CA
certificates), and use `traffic-e2e record` as the container entrypoint. The
controller runs as root and starts the real foreground Source command as 998:998.
Its deployment caller owns image builds, container startup, ports and mounts;
record does not build images or manage Docker. A typical deployment is:

```bash
docker build -f .traffic-e2e/Dockerfile.recording -t source-recording .
docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 4080:4080 -v /absolute/recording-data:/data/traffic-e2e \
  source-recording --data-root /data/traffic-e2e --source-workdir /app \
  -- <source-command> [args...]
```

Keep Source's real business configuration. Mount project Recorder configuration
and its referenced source traffic policy when needed. The default HTTP include
rule covers all methods and paths; existing exclusions still apply. Keep
Source and Recorder on separate loopback ports in the container namespace.
For a host bind mount, set `TRAFFIC_E2E_ARTIFACT_OWNER` to the host user's numeric
UID:GID so completed evidence remains privately readable by that user.

## Coordination And Completion

Without coordination, wait for direct HTTP requests. With `--coordination redis`,
provide a reachable `--advertise-url` and explicit coordination Redis URL through
`TRAFFIC_E2E_RECORDING_REDIS_URL`. Never infer coordination from Source REDIS_URL.
The address is registered after readiness; reservations are released after case
finalization. One local slot remains mandatory in both modes.

One process creates one run. `--run-id` is optional; record generates and reserves
its own UTC identity. Stop normally and retain the exact finalized manifest.
Never select or edit a running or failed recording to make verification pass.

Persist the data root. Recordings live under
`<data-root>/.traffic-e2e/local/artifacts/recordings/<run-id>/`; encrypted headers
require private access to the persistent `.traffic-e2e/local/secrets` key.
Source and Target must never read private recording evidence or key material.

## Rewrite Handoff

Expose the entire completed batch under the initialized target's
`.traffic-e2e/local/artifacts/recordings/<run-id>/`. Make its matching encryption
key privately available at `.traffic-e2e/local/secrets/traffic-e2e-enc.sec`;
preserve restrictive permissions and do not replace a different existing key.
Replay does not need the recording CA private key. No import command is needed.

`backend-rewrite next` consumes this evidence. Optional `recording_run_id` in
local `.traffic-e2e/regression.yaml` pins the batch; otherwise the engine discovers
completed evidence and retains its identity. Missing or rejected evidence returns
`input_required`. Capture-policy refresh requires a newer external batch;
recordings already present when refresh begins cannot satisfy it. The caller
supplies completed comparison evidence separately when its gate is required.

Recorder policy changes use supported plan/apply commands and require new capture.
Old JSONL is immutable. Backend rewrite only consumes completed external batches.
