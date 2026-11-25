# Source Review Rules

Review the integrated diff against Source behavior and the Target repository's
requirements. Run the required checks on the exact committed candidate.

- Confirm affected routes, status and error mapping, dependency requests and
  transactions, startup inputs, configuration, and shutdown behavior against
  Source where the findings apply.
- Check changed files for clear ownership and public entrypoints that exercise
  normal Target behavior. Limit changed production Rust files to 1,000
  complete physical lines, counting comments and blank lines. See
  [target code rules](target-code-rules.md).
- Follow every added task launcher to its trigger and all callers. Confirm
  bounded admission, ownership, cancellation, error handling, and shutdown.
  A callback registered at startup can still execute per request.
- Keep Replay controls, private state, generated addresses, and recorded
  payloads outside Target product code and production configuration.

Return Source references for behavior decisions, checks and outcomes, and any
unresolved findings to the coordinator. The full Source Session verifies the
integrated candidate.
