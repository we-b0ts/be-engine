# Breeze SDK Verification

Verify every new or changed resource package against the modes it supports.

## Descriptor Tests

- Parse valid source descriptors for the applicable resource identities.
- Reject malformed, duplicate, conflicting, and out-of-range entries.
- Prove deterministic selection independent of directory iteration order.
- Reuse the exact port of one compatible existing descriptor.
- Ignore `breeze_sdk.lock` and generated `*.sock` files.

## Independent-Startup Tests

- Create a format-compatible descriptor only when the exact identity is
  absent.
- Serialize concurrent registration with the shared lock and rescan after
  acquiring it.
- Select only eligible random ports and create the descriptor atomically.
- Bound listener readiness and fail startup on registration or readiness
  failure.
- Preserve all unrelated descriptors.

## Replay And Comparison Tests

- Fail replay startup without filesystem mutation when an exact descriptor is
  absent, malformed, duplicate, or conflicting.
- Use the exact recording-time descriptor port without allocation in replay.
- Prove protocol-default ports are never substituted.
- Prove source and candidate reuse the same descriptor and listener during
  comparison.

## Client Lifecycle Tests

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
