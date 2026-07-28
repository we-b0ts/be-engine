# Breeze SDK Verification

Verify every new or changed resource package against the descriptor policies
it supports.

## Descriptor Tests

- Parse valid source descriptors for the applicable resource identities.
- Reject malformed, duplicate, conflicting, and out-of-range entries.
- Prove deterministic selection independent of directory iteration order.
- Reuse the exact port of one compatible existing descriptor.
- Ignore `breeze_sdk.lock` and generated `*.sock` files.

## Policy Tests

- `RequireExisting` reuses one exact descriptor and fails without mutation
  when it is missing.
- `EnsurePresent` reuses one exact descriptor and registers it when missing.
- `CreateNew` fails without mutation when one exact descriptor exists and
  registers it when missing.
- Every policy rejects malformed, duplicate, conflicting, and out-of-range
  claims without mutating the directory.
- No policy rewrites, renames, deletes, replaces, or renumbers an existing
  descriptor.

## Registration Tests

- Serialize concurrent registration with the shared lock and rescan after
  acquiring it.
- Select only eligible random ports and create the descriptor atomically.
- Bound listener readiness and fail startup on registration or readiness
  failure.
- Preserve all unrelated descriptors.

## Client Lifecycle Tests

- Prove each `brz-*` package takes a logical identity and descriptor policy,
  invokes the shared descriptor library, and constructs its own client.
- Prove normal application startup does not depend on a descriptor executable,
  per-resource CLI enumeration, or descriptor-derived address variables.
- Prove adding a resource does not require changing the project CLI.
- Prove protocol-default ports are never substituted.
- Validate startup, configuration, health, normal operations, reuse, and
  shutdown.
- Bound connection, operation, retry, and shutdown waits.
- Exercise resource-specific error mapping and fallback behavior without
  moving business semantics into the SDK.
- For Motan, verify the complete reusable SDK boundary: protocol, discovery,
  routing, codec, transport, deadlines, retries, connection reuse, health, and
  shutdown, independently from any business service interface or method
  contract.
- Prove capability tests own SQL, keys, messages, RPC methods, provider DTO
  mapping, and cross-resource orchestration rather than importing them into the
  Breeze package.
- Run repository-focused tests, formatting, linting, and architecture checks
  required by the consuming or standalone SDK repository.
