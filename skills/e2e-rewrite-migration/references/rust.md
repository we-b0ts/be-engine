# Rust Rewrite Guidance

Use this reference only when Rust is the target language.

## Defaults

For an empty target repo, initialize with `cargo init`, then add the smallest
Axum + Tokio service skeleton needed to run the first recorded E2E and a normal
service entrypoint exposed through `scripts/<project>-cli start`. Do not build a
full production platform before the first recorded scope is proven.

Default stack:

- Axum for HTTP routing
- Tokio for async runtime
- Serde for JSON serialization and deserialization
- `thiserror` for domain/library errors
- `anyhow` for app startup, wiring, and test utilities
- `sqlx` for async SQL access when database behavior is needed
- a small config loader using the target repo's preferred format; YAML is a
  reasonable default when the repo has no convention

Use stable mainstream dependency versions that fit the target repo. Do not
hard-code dependency versions in the migration skill output.

## Architecture

Keep the implementation small and behavior-focused:

- choose the Rust module layout before writing handler/service code
- use module names that fit the repo and source domain; do not treat this skill
  as prescribing exact names
- route handlers should parse inputs, call service logic, and render responses
- service or use-case modules should own business behavior
- store/repository/client traits should isolate database and external dependency
  access
- provide a real implementation for normal runtime, such as a `sqlx` repository
  when the source behavior reads or writes SQL
- provide a recorded/mock implementation only for E2E replay
- make `main` or the default server path construct the real implementation from
  normal configuration, not from a case directory
- tests should drive recorded requests and dependency mocks, not private
  implementation details
- config should be explicit enough to isolate real external services during E2E
- avoid putting a migrated API entirely in `src/lib.rs` and `src/main.rs`

Preserve API, database query semantics, and external protocol behavior unless
the user explicitly approves a contract change. If a recorded case appears to
preserve a source bug, reproduce the recorded behavior first and note the
suspected bug.

For SQLx/MySQL code, map row decode types from explicit schema evidence. Prefer
semantic `dependencies.jsonl` columns with `family`, `sql_type`, `unsigned`,
`bits`, and `nullable`; otherwise use a user-provided schema source. Do not map
Rust types only from Go/Java/Python model fields. For example, `family:
integer`, `sql_type: INT`, `unsigned: true`, `bits: 32` must not decode into
`i32`; use an unsigned or wider Rust type.

For a new Rust service, design a small module map before coding. Common choices
include names like `api`, `http`, `handler`, `service`, `store`, `repository`,
`model`, `domain`, `client`, `adapter`, `util`, `config`, and `app`, but none of
these names is required. Pick names that make the current slice readable and
that can grow with the next API.

Create only modules needed by the current slice. `main.rs` should be
bootstrap-only: parse args/config and start the server. `lib.rs` should mostly
export modules or expose an app factory. Do not let either file become the
catch-all implementation file. Recorded repositories or mock clients should
live under `tests/support/` or an equally isolated test-support module unless
the target repo has a different established pattern.

## E2E And Compatibility

The recorded E2E is the primary contract. For JSON responses, compare parsed
JSON values, not serialized bytes. Object key order, whitespace, and pretty
formatting do not matter. Field presence and value kind do matter: missing,
`null`, and `""` are three different outputs. Only configured ignores may relax
headers or body fields. Use byte-level response compatibility only for non-JSON
bodies or explicit exact-byte modes.

For Rust JSON APIs, define wire DTOs that preserve the source API contract. Do
not add `skip_serializing_if` or default omission unless the recorded/source
response actually omits the field. Represent recorded `null` as `Option<T>`
without skipping serialization, recorded empty strings as `String`, and absent
fields as omitted fields. `HashMap` or other map-backed JSON objects are
acceptable for JSON structural E2E only when field presence and values are
correct; they are not suitable for exact-byte assertions.

Use recorded dependency mocks for tests. Do not connect to real DBs, queues,
caches, or third-party services during recorded E2E unless the target repo
already has an explicit local/test isolation strategy.

Do not make `main` or the default server startup load recorded case data. A
useful Rust shape is:

- `trait UserRepository` or equivalent dependency boundary
- `SqlxUserRepository` for normal runtime
- `RecordedUserRepository` or equivalent in test support for recorded E2E tests
- shared handler/service code parameterized over the boundary
- `app_from_env` or equivalent for normal runtime wiring
- `src/main.rs` that runs the server for API/service migrations
- `config/default.yaml` or equivalent committed development config
- `scripts/<project>-cli` wrapping `start`, `e2e`, `check`, and `doctor` when
  no stronger repo convention exists

The migration is incomplete if only the recorded repository exists for an API
that normally depends on a database or external service, or if the crate has no
normal runnable server entrypoint for a migrated HTTP API.

## Config And Commands

Development startup should read `config/default.yaml` or the repo's equivalent
committed config by default. Support an explicit config path, such as
`--config`, and allow environment variables to override deploy-time values.
Keep `config/local.yaml` and `.env.local` ignored when they contain local
secrets or machine-specific settings.

Prefer `scripts/<project>-cli` as the Rust migration command facade when the
repo has no existing Makefile, justfile, or script convention. The facade should
wrap `cargo run`, focused recorded E2E, Cargo quality gates, and basic config
diagnostics so future agents can use stable commands instead of rediscovering
Cargo invocations.

## Quality Gate

Run these commands before completing a Rust migration unless the target repo has
stricter equivalents:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

If the target repo already defines focused E2E commands, run the focused command
first, then the broader relevant checks.

For API/service migrations, also verify a normal startup path through the
command facade. When real dependencies are unavailable, prefer lazy connection
pools or configuration validation so the service can reach startup without
reading recorded fixtures. Record the exact command and result in
`.migration/e2e.yaml`.
