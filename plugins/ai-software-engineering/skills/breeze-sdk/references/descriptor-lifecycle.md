# Breeze Descriptor Lifecycle

Use this reference for consumer-side descriptor discovery, registration, and
mode-specific mutation authority.

## Fixed Directory And Filename Contract

Use:

```text
/data1/breeze/socks
```

The Java Breeze SDK creates empty files whose names encode configuration. The
common TCP forms are:

```text
<domain>+3+config+v1+<group>+all:<namespace>@<socket-type>:<port>@<protocol>
<domain>+3+config+cloud+<type-code>+<group>+<namespace>[#<topic>]@<socket-type>:<port>@<protocol>
```

Preserve the complete source identity: domain, group, namespace, optional
topic, type code, socket type, and protocol. Do not infer these fields from the
target package name.

The Breeze service accepts descriptor names with exactly three `@`-separated
fields, parses the TCP port from the second field, initializes discovery for
the service identity, and listens on that port. Treat a second descriptor for
an already loaded service with a different port or protocol as a conflict, not
live reconfiguration.

Ignore the SDK coordination file and generated Unix sockets when discovering
TCP descriptors:

```text
/data1/breeze/socks/breeze_sdk.lock
*.sock
```

## Deterministic Resolution

Parse and validate filenames before using extracted values. Resolve the
complete logical identity without relying on directory iteration order.
Require exactly one compatible descriptor and reuse its port.

Fail startup for malformed candidates that claim the resource, duplicate
identity, conflicting protocol or identity fields, or an out-of-range port.
Never silently choose the first candidate.

## Independent Startup

Independent service startup is the only target mode allowed to register a
missing exact descriptor. Require the genuine Breeze service and shared socks
directory, then:

1. lock `/data1/breeze/socks/breeze_sdk.lock`;
2. rescan all descriptor filenames while holding the lock;
3. reuse an exact identity match when one now exists;
4. otherwise randomly select an eligible TCP port, rejecting registered,
   reserved, out-of-range, and currently occupied ports;
5. atomically create the complete format-compatible descriptor filename
   without changing unrelated files;
6. release the lock; and
7. wait with a bounded deadline for Breeze to scan the descriptor and listen
   on the selected port.

Registration failure or listener timeout fails startup. Do not renumber an
existing resource, create a private replacement socks directory, or delete
another process's descriptor.

## Recording

Standard Platform recording mounts the same host `/data1/breeze/socks`
directory into the source and Breeze containers. The source Java SDK creates
missing descriptors during startup; Breeze scans them and listens on the
selected ports. Recording preserves the SDK-selected port as dependency-target
identity.

Consumer SDK implementation is not part of recording initialization. The
recording workflow owns topology, mounts, and source behavior; this skill owns
the target SDK behavior that later consumes the resulting identity contract.

## Replay

Replay is strictly read-only. Before target startup, resolve every required
resource to exactly one descriptor and use its recording-time TCP port for the
replay-intercepted host.

Replay must not allocate a port or create, rewrite, rename, or delete any
descriptor. If an exact descriptor is absent or invalid, fail startup as
blocked: the recording artifact, mount lifecycle, or resource identity
evidence is incomplete. Do not manufacture a descriptor from a recorded
target port or substitute protocol defaults such as `3306`, `6379`, `9092`, or
`11211`.

## Comparison

Comparison recording uses one genuine shared Breeze instance for source and
candidate. Both processes use the same socks directory and complete resource
identities. The source normally establishes the descriptor; the candidate
must resolve and reuse the exact selected port rather than allocate another.

## Compatibility References

Use the Java SDK's identity, filename construction, and synchronization
behavior as the client compatibility reference:

```text
com.weibo.api.datamesh.common.utils.SocketFileUtil
com.weibo.api.datamesh.common.sockdata.SockConstructor
com.weibo.api.datamesh.common.sockdata.SockManager
```

Use the Breeze listener implementation as the server-side reference:

```text
https://github.com/weibocom/breeze
context/src/lib.rs
agent/src/main.rs
agent/src/service.rs
```
