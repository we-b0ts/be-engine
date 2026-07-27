# Platform Breeze Resource Development

This repository uses Platform Breeze for shared database, cache, and messaging
middleware access. Treat the socks descriptor identity and selected port as
part of the runtime and traffic compatibility contract.

## Contents

- [Package Scope](#package-scope)
- [Socks Descriptor Contract](#socks-descriptor-contract)
- [Resource Registration](#resource-registration)
- [Recording And Replay](#recording-and-replay)
- [Implementation Contract](#implementation-contract)
- [Verification](#verification)

## Package Scope

Treat `crates/breeze/` as a closed namespace. Its immediate package directories
MUST be a subset of this exact allowlist:

- `mysql` (`brz-mysql`);
- `redis` (`brz-redis`);
- `memcached` (`brz-memcached`);
- `kafka` (`brz-kafka`);
- `mcq` (`brz-mcq`);
- `queueservice` (`brz-queueservice`).

No other dependency may live under `crates/breeze/` or use a `brz-*` package
name. Motan, HTTP, and other service or RPC clients belong to provider- or
capability-owned client boundaries outside `crates/breeze/`. Traffic passing
through the Breeze runtime or `breeze.recording` does not change code
ownership.

Each allowlisted package owns resource discovery, descriptor reuse and
registration, connection or producer lifecycle, timeouts, retries,
enablement, health, and shutdown. Business SQL, cache keys, messages,
serialization, and fallback policy remain with the owning capability.

## Socks Descriptor Contract

Use the fixed directory:

```text
/data1/breeze/socks
```

The Java Breeze SDK creates empty files whose names carry the configuration.
The common TCP forms are:

```text
<domain>+3+config+v1+<group>+all:<namespace>@<socket-type>:<port>@<protocol>
<domain>+3+config+cloud+<type-code>+<group>+<namespace>[#<topic>]@<socket-type>:<port>@<protocol>
```

Do not infer `type-code`, `socket-type`, or `protocol` from the Rust package
name. Preserve the values used by the source SDK and the exact resource
identity: domain, group, namespace, optional topic, type code, socket type, and
protocol.

The Breeze service scans its configured service path every second. It accepts
descriptor names with exactly three `@`-separated fields, parses the TCP port
from the second field, initializes discovery for the service identity, and
listens on that port. A second descriptor for an already loaded service with a
different port or protocol is a conflict, not a live reconfiguration.

Ignore the SDK lock file and generated Unix `.sock` files when discovering TCP
descriptors:

```text
/data1/breeze/socks/breeze_sdk.lock
*.sock
```

## Resource Registration

Resolve the complete resource identity against existing descriptor filenames
before allocating anything. Require exactly one compatible descriptor and
reuse its port. A malformed descriptor, duplicate identity, conflicting
protocol, or out-of-range port is a startup error.

During independent service startup, a missing exact descriptor may be
registered when the genuine Breeze service and shared socks directory are
available. Preserve the descriptor format and coordinate allocation with other
SDKs and services:

1. lock `/data1/breeze/socks/breeze_sdk.lock`;
2. rescan existing descriptor filenames while holding the lock;
3. reuse an exact group, namespace, and topic match when present;
4. otherwise randomly select an eligible TCP port, rejecting registered,
   reserved, out-of-range, and currently occupied ports;
5. atomically create the complete descriptor filename in the required format
   without changing unrelated files;
6. release the lock and wait with a bounded deadline for Breeze to scan the
   descriptor and listen on the selected port.

Do not treat the allocation algorithm as permission to renumber an existing
resource. Do not create a private replacement socks directory, delete another
process's descriptor, or silently continue after registration or listener
readiness fails.

## Recording And Replay

Standard Platform recording mounts the same host
`/data1/breeze/socks` directory into the source and Breeze containers. The
source business container creates its descriptors during startup when they are
missing, and Breeze scans those files and listens on their selected ports. The
source SDK-selected TCP port is recorded as part of the dependency target
identity.

Replay has a strict precondition: the recording-created descriptor files
already exist in the mounted `/data1/breeze/socks` directory. Before the target
starts, resolve every required resource to exactly one descriptor, extract its
recording-time TCP port, and connect to the replay-intercepted host on that same
port. Replay MUST NOT allocate a port or create, rewrite, rename, or delete a
descriptor. If an expected descriptor is absent, stop as blocked because the
recording/replay directory lifecycle or mount contract was violated. Do not
substitute protocol defaults such as `3306`, `6379`, `9092`, or `11211`, and
do not manufacture a replacement descriptor from a recorded target port.

Comparison recording uses one genuine shared Breeze instance for source and
candidate. Both must use the same socks directory and resource identities.

## Implementation Contract

Expose resource identity and bounded operation settings to application code;
do not expose arbitrary caller-selected Breeze ports. Construct long-lived
clients, pools, producers, and consumers once in the composition root and reuse
them.

Keep descriptor parsing and matching deterministic and independent from
directory iteration order. Validate filenames before using any extracted
value. Never log descriptor-derived credentials or committed secret values.

Use the Java SDK's descriptor identity, filename construction, and
synchronization behavior as the compatibility reference:

```text
com.weibo.api.datamesh.common.utils.SocketFileUtil
com.weibo.api.datamesh.common.sockdata.SockConstructor
com.weibo.api.datamesh.common.sockdata.SockManager
```

Use the Breeze service listener behavior as the server-side reference:

```text
https://github.com/weibocom/breeze
context/src/lib.rs
agent/src/main.rs
agent/src/service.rs
```

## Verification

For every new or changed `brz-*` implementation, test:

- valid source descriptor parsing for the applicable resource types;
- rejection of malformed, duplicate, conflicting, and out-of-range entries;
- exact reuse of an existing resource port;
- independent-startup random eligible-port allocation and serialized,
  format-compatible descriptor creation when the exact resource is absent;
- bounded listener readiness and dependency operation deadlines;
- replay startup failure without any filesystem mutation when the
  recording-time descriptor is absent;
- replay use of the exact recorded descriptor port without allocation; and
- normal startup, health, shutdown, and resource reuse.
