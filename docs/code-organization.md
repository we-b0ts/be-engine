# Code Organization

Use this file before changing product code. It defines the repository's module
review, naming, dependency, and size rules.

## Package Shape

Keep this repository as one Rust crate unless the user asks for a workspace,
the project gains multiple deployable artifacts, or multiple real packages need
a shared library. Ask before creating a workspace when the boundary is unclear.

## Pre-Change Review

Before adding behavior, inspect the target unit, its parent namespace, and its
direct collaborators. Keep the current boundary only when all are true:

- the unit has one owner and one primary reason to change
- its name covers the new behavior
- the change does not add an unrelated domain, layer, lifecycle, or side effect
- collaborators can use a small interface without exposing private details

Otherwise, make the smallest boundary adjustment needed by the current change
before adding behavior. Preserve public interfaces and recorded formats unless
the user explicitly requests a contract change. Do not reorganize unrelated
domains or create empty placeholder modules.

## Naming And Cohesion

Names are responsibility contracts. Name code by its current owner, not by
history, the first implementation, or a technology it happens to use.

Organize namespaces from stable ownership to implementation detail:

1. product capability or domain
2. cohesive sub-capability
3. architectural role
4. protocol, transport, framework, database, or vendor adapter

The parent must naturally describe every child. Use directories and ordinary
Rust modules for ownership levels, and short leaf filenames for direct
responsibilities:

```text
domain/capability/session.rs
```

Do not simulate that hierarchy with names such as
`domain_capability_session.rs`, and do not repeat parent names in child files.
Choose the parent by ownership rather than mechanically copying a string
prefix. Keep paths to roughly two to four meaningful levels.

Group code by shared domain responsibility and lifecycle, not merely because it
uses TCP, JSON, a database driver, or a common context. Parsing, runtime
orchestration, persistence, recording, and protocol I/O are separate change
axes unless one narrow unit genuinely owns them together.

Avoid vague owners such as `common`, `misc`, `utils`, `helpers`, `manager`, or
`processor` when a precise domain or role exists. Prefer roles such as parser,
matcher, registry, writer, repository, client, adapter, or runtime. A unit that
can only be described with "and", "also", or "but it also owns" needs a
boundary review.

## Refactor Triggers

Review and normally extract before extending code when any signal appears:

- the new behavior does not fit the current name or primary reason to change
- a protocol-, transport-, vendor-, or first-use-case-named unit starts owning
  broader orchestration or another domain
- one file mixes transport, semantic decoding, business orchestration,
  persistence, recording, or runtime lifecycle
- three or more sibling product files share a semantic prefix and their
  suffixes are responsibilities of one owner or lifecycle
- a filename repeats two or more ownership levels
- a new file would extend prefix sprawl instead of a real namespace
- implementation requires copied code, wider visibility, or a catch-all helper
- normal runtime code would depend on replay-only or test support
- production `include!` composition is added or extended
- a code-size gate below is reached

Three or more same-prefix siblings are a possible implicit namespace. If they
share one owner, lifecycle, and entry point, promote them to an ordinary module
before changing behavior in that cluster and remove the repeated prefix. A
documented keep-as-is decision is acceptable only when the files are genuinely
independent or follow an established flat convention.

`include!` does not create a module boundary and does not satisfy a size or
cohesion gate. Use it in production only for generated code, macro input, or a
similarly explicit reason. Ordinary implementation code should use `mod` and
narrow `pub(super)` or `pub(crate)` interfaces.

## Dependency Direction

- protocol parsers do not write files or mutate recording directories
- record writers do not parse protocol bytes
- gateway and proxy modules orchestrate sessions but do not own semantic codecs
- config loading stays separate from runtime behavior
- adapters do not control their caller's runtime or lifecycle
- normal recorder and replay startup do not depend on tests or fixtures

Circular dependencies, widespread visibility, shared mutable global state,
implementation types leaking through interfaces, or unrelated sibling changes
are coupling signals. Sharing a small helper does not justify depending on an
unrelated large module.

## Code-Size Gates

Apply these gates to product source files and to logical modules assembled with
`include!`:

- over 600 lines: review for mixed responsibilities
- over 800 lines: split or document the single cohesive responsibility
- over 1000 lines: hard stop until the touched responsibility is extracted,
  unless the user explicitly forbids refactoring for that task

Current over-1000-line hotspots are `src/mysql_semantic.rs`, `src/recorder.rs`,
and `src/tcp_gateway.rs`. When a task touches one, extract only the relevant
semantic, recording, routing, connection, or protocol responsibility first.

Run `scripts/check-code-organization`. By default it checks changed and
untracked product files; set `CODE_ORG_BASE=origin/master` or another base to
check the full branch delta. The script is a size backstop, not a replacement
for the ownership and cohesion review.

## Current Boundaries

- `main.rs`: CLI and binary bootstrap only
- `lib.rs`: application wiring, shared state, and stable exports
- proxy/gateway modules: connection and request orchestration
- protocol/semantic modules: parsing, encoding, and semantic interpretation
- recorder/event/run/summary modules: capture, persistence, and reporting
- replay modules: recorded dependency matching and replay lifecycle
- config, TLS, DNS, and process lookup: focused infrastructure concerns

Prefer these boundaries while they remain accurate. When the refactor triggers
show that a flat prefix or current parent no longer expresses ownership, choose
the smallest real namespace that does.

## Completion Check

```bash
scripts/check-code-organization
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Do not declare completion when a touched product file or logical `include!`
module violates the hard gate, or when the change weakens naming accuracy,
cohesion, dependency direction, or runtime/test separation.
