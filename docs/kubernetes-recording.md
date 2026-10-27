# Kubernetes dependencies during external recording

`traffic-e2e record` can record Source traffic to Kubernetes Services while the
recording container runs outside the cluster. The controller uses kubectl to
discover Service TCP ports and supervise port-forward processes. Source retains
its original business URLs. Local cluster DNS resolution and direct routing to
Service or Pod IPs are not required; the controller must reach the Kubernetes API.

Configure the existing project `.traffic-e2e/project.yaml`:

```yaml
recorder:
  kubernetes:
    kubectl_binary: /usr/local/bin/kubectl
    kubeconfig: /run/kube/config
    # context: recording-cluster
  upstream_routes:
    - host: wegent-chat-shell-web.wb-plat-ide.svc.cluster.local
      via:
        type: kubernetes_port_forward
        namespace: wb-plat-ide
        service: wegent-chat-shell-web
```

There are no `port` or `service_port` fields. The controller reads
`Service.spec.ports`, selects TCP ports and starts one supervised forward for each
distinct namespace/Service/port. Different host aliases for one Service share
these processes. Each forward listens on a kubectl-allocated IPv4 loopback port.
The runtime routing table maps the original hostname and Service port to that
listener, independently of the Pod's `targetPort` chosen by kubectl.

The default binary is `kubectl` on PATH. If `kubeconfig` or `context` is omitted,
kubectl uses its normal credential/context selection, including `KUBECONFIG`.
Paths refer to the recording controller's filesystem; use an absolute path.
Projects provide kubeconfig and referenced credentials through read-only runtime
mounts, or explicitly package a portable kubeconfig in their dedicated recording
image through a private build context. Keep its parent directory root-owned
`0700` and the file root-owned `0600`, inaccessible to Source UID 998. Packaged
credentials remain in image layers and require a rebuild to rotate. Keep them
outside Git and the shared engine/kubectl images. Exec-based authentication also
needs its plugin in the recording environment. The recorder never saves these
credentials in traffic artifacts. Copy the executable from the independent
[kubectl distribution image](development.md#kubectl-distribution-image).

The controller needs permission to read Services, discover/select Pods and open
`pods/portforward` connections in the configured namespaces. The supplied
kubeconfig selects the cluster; only explicitly declared routes enable forwarding.
This first implementation uses port-forward for declared routes even when run
inside a cluster; it does not infer direct Service reachability from Pod-related
environment variables.

## Startup, capture and shutdown

Before Source starts, the controller queries Services and waits for every local
listener notification. Kubernetes preparation shares one deadline from
`--startup-timeout-seconds`. Missing tools, credential/permission failures,
unsupported Services, output limits and readiness timeouts fail startup and
clean up all children already created. With no routes, no Kubernetes commands
are executed and no cluster credentials are needed.

For configured hosts, fake DNS allocates a fake IP without querying real DNS.
The TCP gateway resolves its upstream through the prepared routing table while
recording the original hostname and port. HTTP Host and HTTPS SNI keep their
ordinary behavior; HTTPS upstream certificate verification stays enabled.
MySQL and other supported dependency protocols retain their existing capture
semantics. The controller and kubectl run outside Source UID 998's interception
scope, so Kubernetes control traffic is not captured as business dependencies.

HTTP recording through these declared routes uses a separate upstream client
that does not retain idle connections. Every HTTP exchange opens a new business
connection through the existing kubectl tunnel. An active response, including
SSE, keeps its connection until the complete response or actual termination.
Ordinary HTTP upstreams retain their existing connection pooling. HTTPS routes
already establish a fresh TLS connection for each exchange and keep strict SNI
and certificate verification.

This avoids reusing an upstream socket during port-forward's delayed propagation
of a server's idle close. It does not depend on the business service's keep-alive
timeout, change Source configuration, or replay a failed business request.

Any unexpected port-forward exit, including exit code zero after readiness,
immediately fails the recording and stops Source through ordinary supervised
shutdown. The controller never restarts the forward. Actual interrupted exchanges
remain in their semantic evidence; Recorder never resends dependency requests
to hide a failed connection. Initial discovery, permission and readiness errors
retain their ordinary startup failure behavior.

Normal shutdown retains forwards until Source stops and accepted requests drain,
then terminates and reaps scoped process groups before Recorder finalization.

Each forward logs its process ID, Service identity, local listener, lifetime,
handled-connection count and exit code/signal when it exits. Requested shutdown
is logged separately from an unexpected exit; an unexpected exit with code zero
is still a forwarding failure. Stderr is reduced to static operation and cause categories,
including lost connections, refused/reset connections, timeouts, authentication,
TLS and stream errors. The exit log and returned error retain the last eight
categories, total stderr lines and unknown-line count. Raw stderr, authentication
plugin output, URLs and credential values are never logged or saved in artifacts.
Unknown lines retain only their category and count.

After child exit, the controller drains buffered output for at most 100 ms so an
immediate exit cannot hide its final diagnostic or connection notification.
`stderr_drained=false` indicates
that the pipe did not reach EOF within that bound or failed its existing bounded
line validation; diagnostic collection does not replace the original exit status.
The same summary appears in ordinary recording-container logs and the final error.

## Supported scope

- TCP ports declared by Services that select Pods, including headless Services.
- At most 256 distinct forwarded Service ports per recording process.
- Exact host matching, case-insensitive and allowing a trailing DNS dot.
- Ports are discovered once per startup; restart to pick up Service port changes.

ExternalName Services, selectorless Services and Services without TCP ports fail
startup. UDP traffic and undeclared TCP ports for a configured host are rejected
instead of being sent to another local service. A host cannot also be a static
`dns_mock.hosts` entry or match DNS bypass. This adds transport access, not new
protocol capture support; for example, gRPC still needs separate semantic support.

Replay uses the original recorded logical endpoints and never loads the local
forwarding addresses or starts Kubernetes clients. The recording kubeconfig and
access to the live cluster are not needed for dependency replay.

The opt-in [container lifecycle regression](../tests/manual/kubernetes_recording/README.md)
exercises Source startup, real DNS/TCP interception, successful recording and
startup/runtime failures with a synthetic kubectl and no external network.
