# Breeze Descriptor Compatibility

Use this reference for a target resource whose Breeze listener endpoint is
derived from descriptor files.

## Storage And Identity

The established shared roots are:

```text
/data1/breeze/socks
/data1/breeze/snapshot
```

The socks directory is live registration state and the snapshot directory is
source-compatible discovery input. Neither is application configuration. Use
them in place; do not copy, mirror, translate, or stage them into a
project-local directory.

The Java Breeze SDK creates empty descriptor files whose names encode the
complete resource identity. Common TCP forms are:

```text
<domain>+3+config+v1+<group>+all:<namespace>@<socket-type>:<port>@<protocol>
<domain>+3+config+cloud+<type-code>+<group>+<namespace>[#<topic>]@<socket-type>:<port>@<protocol>
```

Preserve every source-proven identity field, including domain, group,
namespace, optional topic, type code, socket type, and protocol. Never infer
identity from a package name or protocol default. Ignore the coordination file
`breeze_sdk.lock` and generated `*.sock` files when scanning TCP descriptors.

## Deterministic Resolution

Parse and validate filenames before using extracted values. Resolve the full
logical identity independently of directory iteration order and require
exactly one compatible descriptor. Fail startup when the requested identity is
missing, malformed, duplicated, conflicts on socket type or protocol, or uses
an invalid port. Never silently choose the first candidate or substitute a
default port.

The traffic-e2e-controlled target runtime consumes existing descriptors and
must not create, rewrite, rename, delete, replace, or renumber them. The target
SDK accepts only generic topology inputs such as Breeze host, descriptor root,
and bounded readiness settings; it never consumes Replay state, recordings,
dependency artifacts, or observed target ports.

For a normal production runtime, add descriptor registration only when the
pinned source SDK proves that the target owns it. Preserve the source identity,
locking, rescan, port eligibility, atomic creation, listener-readiness, and
conflict behavior. Do not introduce a generalized `EnsurePresent` or
`CreateNew` policy without an evidenced production caller and source contract.

## Acceptance

Verify that the implementation:

- parses valid source descriptors and ignores only known coordination/socket
  files;
- deterministically rejects missing, malformed, duplicate, conflicting, and
  out-of-range entries without mutation;
- reuses the exact port of one compatible descriptor;
- constructs the resource's long-lived client from the resolved listener and
  reaches readiness within a bounded deadline; and
- keeps descriptor identity and resolution out of project-CLI resource
  branches and capability business code.

Use the pinned Java SDK's `SocketFileUtil`, `SockConstructor`, and
`SockManager` implementations as the client compatibility authority. Use the
matching Breeze listener implementation in `context/src/lib.rs`,
`agent/src/main.rs`, and `agent/src/service.rs` as the server authority.
