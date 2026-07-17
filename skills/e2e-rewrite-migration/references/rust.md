# Rust Rewrite Guidance

Use this reference only when Rust is the target language. Apply the generic
runtime and quality contracts from [target-runtime.md](target-runtime.md) and
[implementation-quality.md](implementation-quality.md) first.

## Repository And Runtime

Reuse the target crate layout, async runtime, web framework, config system,
logging stack, and command conventions. For an empty HTTP-service target with
no stronger constraint, Tokio plus a mainstream Tokio-native framework is a
reasonable starting point; add only what the selected capability needs.

Default to one crate for the first capability. Create a workspace only when the
user requests it, the target already uses one, the selected scope contains
multiple deployable artifacts, or a shared crate boundary is already justified
by multiple consumers.

Keep the binary entrypoint focused on arguments, config, diagnostics, wiring,
and startup. Keep library and module roots focused on exports and factories.
Use real Rust modules and narrow interfaces; do not use `include!` or prefix
sprawl as a substitute for ownership boundaries.

Name modules, traits, structs, factories, and adapters from the target domain
and repository convention. This skill MUST NOT prescribe example identifiers
as standard names.

## Genuine Dependency Path

Use the same real dependency interfaces, production adapters, and genuine
protocol clients in normal runtime and recorded E2E. For SQL behavior, run the
actual async database client path; for HTTP, cache, queue, or other protocols,
run the corresponding real client path. Route or intercept emitted traffic at
the replay boundary.

Rust product code, integration tests, test support, and commands MUST NOT read
`dependencies.jsonl` or dependency fixtures to return recorded dependency
results. They MUST NOT read `expected-response.json` outside the final response
assertion. Do not create an alternate recording-backed, fixture-backed, fake,
or in-process dependency implementation for recorded E2E.

Pure local unit tests may use directly constructed inputs, but they cannot
replace recorded E2E or prove external dependency behavior through a fixture or
test double.

## API Compatibility

For JSON APIs, compare parsed JSON structures. Preserve missing, `null`, empty
string, scalar type, and ordered-array semantics. Define wire models that match
the source contract; do not omit fields merely because an optional Rust value
is absent unless the source contract also omits them.

Use byte comparison only for non-JSON bodies or an explicitly configured exact
mode. Keep framework request and response types at the transport boundary and
keep business behavior independent of them.

## Database Types

For SQL-backed behavior, map decode types from explicit semantic schema rather
than source-language model fields or raw protocol flags. Respect signedness,
bit width, nullability, decimal precision, temporal semantics, and byte/text
distinctions. Use a wider compatible Rust type when the recorded or supplied
schema cannot fit a narrower type safely.

Missing schema remains an explicit migration blocker when it can affect runtime
decode correctness.

## Diagnostics

Reuse the target's Rust diagnostics stack. When no convention exists, structured
Tokio-aware tracing with environment filtering is a reasonable default. Keep
startup, request or job, dependency-boundary, and root-cause errors observable
without logging credentials, authorization data, full DSNs, or sensitive
bodies. Read [logging.md](logging.md) only when diagnostics are in scope.

## Quality Gate

Run the target repository's required checks. Without stricter equivalents, run:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

For runnable services, also run the normal-startup smoke defined by the target
repository and clean up any process started for verification.
