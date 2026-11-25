# Standalone Source Recording

Use the single `traffic-e2e record` command inside the prepared Source environment:

```bash
traffic-e2e record --config /etc/traffic-e2e/.traffic-e2e/project.yaml \
  --source-workdir /app --data-root /data/traffic-e2e \
  -- <source-command> [args...]
```

Project configuration is optional. Preserve configured HTTP include/exclude
rules; their default admits all methods and paths. Ingress selects API traffic.
Redis ingress selection can be published with `--api-policy`; it does not change
Recorder capture rules. Source runs as 998:998; the controller owns
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
and its `project.policy` file, preserving repository-relative paths. With no
project YAML, `record --policy PATH` loads the same typed policy Source effects.
With a project YAML, an explicit `--policy` must name that same file. The default HTTP include
rule covers all methods and paths; existing exclusions still apply. Keep
Source and Recorder on separate loopback ports in the container namespace.
For external Kubernetes dependencies, configure `recorder.upstream_routes` with
the original hostname, namespace and Service, plus optional `recorder.kubernetes`
kubectl/kubeconfig/context settings. The controller discovers Service TCP ports
and waits for supervised forwards before starting Source; no port fields are
required. Copy kubectl from its independent distribution image. Supply
controller-private credentials through runtime mounts or an explicitly reviewed
project recording image build. HTTP exchanges through declared Kubernetes routes
use fresh upstream business connections while retaining the existing kubectl
tunnel; active SSE responses keep their connection until completion. Any
unexpected forward exit fails the recording and stops Source without restarting
the forward. Initial startup failures also fail the recording. Existing business
requests are never retried by the engine. Replay never starts these forwards.
See the repository's `docs/kubernetes-recording.md` for the full contract.
For a host bind mount, set `TRAFFIC_E2E_ARTIFACT_OWNER` to the host user's numeric
UID:GID so completed evidence remains privately readable by that user.

## Coordination And Completion

Without coordination, wait for direct HTTP requests. With `--coordination redis`,
provide a reachable `--advertise-url` and explicit coordination Redis URL through
`TRAFFIC_E2E_RECORDING_REDIS_URL`. Never infer coordination from Source REDIS_URL.
The address is registered after readiness. Reservations track active ingress
through response completion. Both modes enforce an ingress concurrency limit
that defaults to eight. Configure it with `--max-inflight-requests` or
`recorder.recording.max_inflight_requests`.

With Redis coordination, optional `--api-policy PATH` / `TRAFFIC_E2E_API_POLICY`
loads gateway JSON (`case-limit`, `includes`, `excludes`) before Source startup.
Recorder publishes it to `<prefix>:api-policy` and clears
`<prefix>:api-counts` before Source starts. Counts reset on every
Redis recording startup; omitting the file overwrites old policy with empty
`includes` (all paths), empty `excludes` (exclude none) and no gateway limit.
Finish the previous round before restarting under the same prefix. Heartbeats
and re-registration never repeat these writes. Invalid input or failed startup
writes fail the run. Shutdown unregisters the owned address while retaining the
policy and counts. Gateway policy refresh follows its ordinary interval.

The gateway limit counts admissions across methods for each API path or
template. Recorder also applies its HTTP include/exclude rules. Direct mode
accepts the Recorder's HTTP rules and concurrency limit.

One process creates one run. When `--run-id` is omitted, Recorder reserves its
own UTC identity. Stop Recorder with SIGTERM or SIGINT so it closes ingress,
gives active requests up to 15 seconds to finish, and marks remaining requests
with an `engine_shutdown` cancellation. Recorder then stops Source and seals
the session. Preserve the complete finalized directory and its manifest.

Persist the data root. Recordings live under
`<data-root>/.traffic-e2e/local/artifacts/recordings/<run-id>/`; encrypted headers
require private access to the persistent `.traffic-e2e/local/secrets` key.
The setting `recorder.recording.encrypt_request_headers` selects header
encryption. Keep private recording evidence and key material outside the Source
and Target processes.

## Rewrite Handoff

Expose the entire sealed session under the initialized Target's
`.traffic-e2e/local/artifacts/recordings/<run-id>/`. Make its matching encryption
key privately available at `.traffic-e2e/local/secrets/traffic-e2e-enc.sec`;
preserve restrictive permissions and do not replace a different existing key.
Replay does not need the recording CA private key. No import command is needed.

Select `recording_run_id` in local `.traffic-e2e/regression.yaml` or pass the
global `--recording-run-id`, then run `be-replay run` for the initialized
Target. Use the same sealed input for Target repairs and obtain a fresh run
when Source workload or capture needs change. See
[Source Session regression](../../be-replay/references/session-regression.md).
