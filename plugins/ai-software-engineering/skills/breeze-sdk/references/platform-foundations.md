# Breeze Platform Foundations

Use this reference for process-wide Breeze logging and TAuth2 foundations.

## Logging

Place the shared logging foundation at `breeze/log` as the `brz-log` package.
Expose the platform `trace`, `debug`, `info`, `warn`, `error`, and `access`
facade on top of `tracing`.

Own subscriber initialization, filtering, structured output, common event and
span fields, request and trace context propagation, and redaction defaults.
Initialize the subscriber once in the application composition root; libraries
never install or replace the global subscriber.

Treat `access` as a first-class structured channel with independent routing and
filtering, not as an alias for `info`. Attach standard request and trace context
automatically. Callers own capability-specific access fields and values;
`brz-log` owns their transport and common envelope. Metrics, sampling policy,
and alert decisions remain with their owners unless a source-proven platform
contract standardizes them.

Verify initialization and duplicate initialization, every facade level,
independent `access` routing and filtering, structured fields, context
propagation, and redaction. Prove libraries can use the facade without
installing or replacing the global subscriber.

## TAuth2

Place the shared authentication foundation at `breeze/tauth2` as the
`brz-tauth2` package. Own source-compatible token acquisition, parsing, claims,
signature verification, and expiry handling.

Fetch the token once during process startup, keep the token and derived
verification state in memory, and refresh the token periodically using the
source-configured interval. TAuth2 does not use a snapshot: never persist its
token or derived seed state to configuration or a local file.

Keep application authorization policy, option-pass whitelists, and
endpoint-specific error mapping in the capability. Verify one startup token
fetch, periodic refresh, and that token and derived verification state remain
in memory without a snapshot or local token/seed file.
