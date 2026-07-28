# Breeze Descriptor Lifecycle

Use this reference for consumer-side descriptor discovery, registration, and
policy-specific mutation authority.

## Contents

- Consumer flow and ownership
- Fixed directory and filename contract
- Deterministic resolution
- Descriptor policies
- Registration and listener readiness
- External topology boundary
- Compatibility references

## Consumer Flow And Ownership

The application composition root supplies a complete logical identity and one
generic descriptor policy to a `brz-*` resource package. The resource package
uses the shared descriptor library, obtains a Breeze listener endpoint, and
constructs the long-lived protocol client.

```text
composition root: identity + policy + generic Breeze settings
  -> brz-memcached / brz-redis / other resource package
  -> descriptor library: resolve or register
  -> Breeze listener endpoint
  -> long-lived resource client
```

Do not insert a project CLI, shell resolver, or per-resource environment
variable between these layers. A project CLI may pass one generic policy,
Breeze host, descriptor directory, and bounded readiness settings. It must not
choose the policy by inspecting runner state or know resource identities or
ports.

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
Distinguish these states before applying the selected policy:

- exactly one compatible descriptor;
- no compatible descriptor;
- malformed descriptor claiming the identity;
- duplicate compatible descriptors; or
- a conflicting socket type, protocol, or identity claim.

Fail startup for malformed candidates that claim the resource, duplicate
identity, conflicting protocol or identity fields, or an out-of-range port.
Never silently choose the first candidate.

## Descriptor Policies

Use a state policy, not a recording or deployment scenario:

| Policy | Exact descriptor exists | Exact descriptor is absent |
| --- | --- | --- |
| `RequireExisting` | reuse it | fail without mutation |
| `EnsurePresent` | reuse it | register a new descriptor |
| `CreateNew` | fail without mutation | register a new descriptor |

Every policy fails for malformed, duplicate, or conflicting claims. No policy
may rewrite, rename, delete, replace, or renumber any existing descriptor.
`CreateNew` means exclusive creation; it does not clean the directory.

## Registration And Listener Readiness

`EnsurePresent` and `CreateNew` share one registration algorithm:

1. lock `/data1/breeze/socks/breeze_sdk.lock`;
2. rescan and validate all descriptor filenames while holding the lock;
3. apply the selected policy to the lock-protected state;
4. randomly select an eligible TCP port when creation remains allowed,
   rejecting registered, reserved, out-of-range, and occupied ports;
5. atomically create the complete format-compatible descriptor filename;
6. release the lock; and
7. wait with a bounded deadline for Breeze to scan the descriptor and listen.

For `EnsurePresent`, a compatible descriptor found during the locked rescan is
reused. For `CreateNew`, the same observation fails with an already-exists
error. Registration failure or listener timeout fails startup. Preserve all
unrelated descriptors.

After any policy returns a port, the resource package must establish bounded
listener readiness before the application becomes ready. This readiness check
does not grant mutation authority to `RequireExisting`.

## External Topology Boundary

The Breeze SDK does not know why a caller selected a policy. Keep recording,
replay, comparison, test, and deployment scenario names out of SDK APIs,
conditionals, errors, and telemetry. The workflow that owns an external
topology maps it to one of the three generic policies before constructing the
application.

The SDK accepts only generic topology inputs such as Breeze host, descriptor
directory, descriptor policy, port eligibility, and listener-readiness
deadline. It never consumes replay sessions, dependency artifacts, recorded
commands, cache keys, or observed target ports.

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
