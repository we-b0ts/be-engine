# Backend Code Organization

Use these rules before and during product-code changes. Treat the initial
module boundary as a hypothesis, then review it again after the implementation
reveals the actual responsibilities.

## Contents

- [Boundary Review](#boundary-review)
- [Naming And Cohesion](#naming-and-cohesion)
- [Refactor Signals](#refactor-signals)
- [Dependency Direction](#dependency-direction)
- [Code-Size Gates](#code-size-gates)
- [Execution Timing](#execution-timing)
- [Completion Review](#completion-review)

## Boundary Review

Before adding behavior, inspect the target unit, its parent namespace, and its
direct collaborators. Keep the current boundary initially only when it has one
owner and primary reason to change, its name covers the new behavior, and the
change does not add an unrelated domain, layer, lifecycle, or side effect.

When a mismatch is already clear, make the smallest enabling boundary change
before adding behavior. When ownership is uncertain, use the smallest
plausible boundary and revisit it as implementation proceeds. Preserve public
contracts unless the task changes them. Do not reorganize unrelated domains or
create placeholder modules.

Existing code is evidence of behavior and constraints, not automatic precedent
for new structure. Preserve verified behavior, but do not spread a legacy
boundary merely for consistency.

## Naming And Cohesion

Name code by its current owner and responsibility, not its history, first use
case, or incidental technology. Organize namespaces from stable ownership
toward implementation detail:

1. product capability or domain;
2. cohesive sub-capability;
3. architectural role;
4. protocol, transport, framework, database, or vendor adapter.

Use real modules or packages for ownership levels. Do not simulate hierarchy
with repeated underscore-separated prefixes or repeat parent names in child
files. Prefer precise roles such as parser, matcher, registry, writer,
repository, client, adapter, or runtime over `common`, `misc`, `utils`,
`helpers`, `manager`, or `processor`.

A unit that can only be described with “and” or “but it also owns” needs a
boundary review. Group code by shared domain responsibility and lifecycle, not
only because it uses the same protocol, framework, or data format.

## Refactor Signals

Review and, when necessary, adjust the smallest relevant boundary when:

- new behavior does not fit the current name or reason to change;
- transport, semantic decoding, orchestration, persistence, or lifecycle are
  mixed without one narrow owner;
- three or more sibling files repeat a semantic prefix for one owner;
- a new file would extend prefix sprawl instead of a real namespace;
- implementation requires copied logic, wider visibility, or a catch-all
  helper;
- production code would depend on replay, fixtures, or test support;
- ordinary production implementation is composed with `include!`; or
- a code-size gate is reached.

`include!` does not establish ownership. Reserve it for generated code, macro
input, or another explicit build-time reason. Use normal modules and narrow
interfaces for ordinary implementation.

## Dependency Direction

Keep protocol parsing separate from persistence, configuration loading
separate from runtime behavior, adapters separate from caller lifecycle, and
production startup separate from test or replay support. Gateways and handlers
may orchestrate a request or session, but should not absorb semantic codecs,
business policy, storage, and process lifecycle together.

Circular dependencies, widespread visibility, shared mutable global state,
implementation types leaking through interfaces, and unrelated sibling
changes are coupling signals. Sharing a small helper does not justify depending
on an unrelated large module.

## Code-Size Gates

Apply this hard backstop to product source files and logical modules:

- over 1000 lines: hard stop until the touched responsibility is extracted,
  unless the user explicitly forbids that refactor for the current task.

The checker emits no line-count warning at or below 1000 lines. Line count is a
hard backstop, not an architecture: a smaller incoherent file still requires
repair, while an evidenced cohesive file within the limit may remain. Do not
maintain static hotspot lists; inspect the current working tree.

Invoke the bundled [check-code-organization](../scripts/check-code-organization)
with the target repository as the working directory. It checks conventional
Rust product roots:
`src/`, `crates/**/src/`, and `apps/**/src/`.

## Execution Timing

- Before modification, inspect the target file’s current size and ownership.
  Do not run a full-repository scan for every focused task.
- After the final product-code edit and before commit, run the checker
  with no arguments. It checks working-tree changes, staged changes, and
  untracked product files. Rerun it if product code changes afterward.
- Before an MR, set `CODE_ORG_BASE` to its target branch and rerun the checker
  so committed and uncommitted changes in the complete branch delta are
  covered.
- Use `--all` only for an initial baseline, architecture review, or explicit
  repository-wide cleanup.
- Skip the checker for documentation, configuration, or skill-only changes
  unless repository instructions require it.

The checker is a deterministic size backstop, not a replacement for ownership
and cohesion review.

## Completion Review

Before claiming completion:

1. confirm touched names and parents still cover their implemented behavior;
2. apply feature-local refactor signals exposed by the implementation;
3. keep unrelated legacy cleanup outside the change;
4. run repository-required format, lint, static analysis, and tests; and
5. rerun behavior checks affected by structural changes.

Do not declare completion when a touched product file violates the hard gate
or when the change weakens naming accuracy, cohesion, dependency direction, or
runtime/test separation.
