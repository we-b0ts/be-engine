<!-- traffic-e2e:boot-boundary:start -->
## Traffic E2E Boot Inputs

`.traffic-e2e/boot/` is an input-only, Git-ignored transport location.

- Only direct process environment, startup arguments, machine-local
  configuration, or a complete authoritative configuration or source-SDK
  snapshot already present at its source may be placed there.
- Never generate its contents from source-process memory, remote responses,
  recordings, logs, debug output, or diagnostics. The directory name or
  Git-ignore status does not establish provenance.
- Never print or commit boot inputs.
<!-- traffic-e2e:boot-boundary:end -->
