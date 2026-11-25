# External Recording Evidence

The deployment caller owns the `traffic-e2e record` process and container.
Place the completed run in the initialized Target's
`.traffic-e2e/local/artifacts/recordings/<run-id>/` directory. Preserve the
entire sealed tree, including `dependency-manifest.json`, `events.tsv`, the
network manifest, indexes, and payload segments. Encrypted headers require
the matching private key at `.traffic-e2e/local/secrets/traffic-e2e-enc.sec`.
Keep the key outside the Target process and preserve its private permissions.

Recorder captures concurrent ingress and dependencies on one Source timeline
from launch through exit. The recording caller selects ingress through the
HTTP gateway rules. Recorder opens ingress at readiness. Optional coordination
Redis handles discovery and ingress reservations. On normal shutdown, Recorder
closes admission and gives active ingress up to 15 seconds to finish.
Remaining active requests receive an `engine_shutdown` cancellation before
Recorder stops Source and seals the run.

Keep ingress paths verbatim, including trailing slashes and repeated
separators. A recorded 404 is normal assertion evidence. Selected ingress
HTTP upgrades, CONNECT, and request trailers fail Session capture. Ordinary
response streams and response trailers have recorded events.

Use the exact 14-digit recording ID when starting the approved round with
`be-replay run --user-confirm --recording-run-id ID`. For missing or incomplete
evidence, obtain a sealed external recording. The work branch retains its
recording across Target repairs. Start a new round when Source workload or
capture needs change. See [Source Session regression](session-regression.md).
