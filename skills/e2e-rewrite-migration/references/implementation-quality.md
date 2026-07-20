# Implementation Quality Contract

Read this reference after selecting one canonical API group and again after its
first successful recorded replay.

## Behavior And Tests

Rewrite behavior rather than source text. Preserve source-visible responses,
dependency roles, required side effects, error semantics, and metrics unless
the user explicitly approves a contract change.

Add focused unit or component tests for non-trivial local logic such as parsing,
serialization, dynamic value strategies, schema conversion, signing, error
mapping, or protocol payload construction. Do not duplicate the full recorded
E2E assertion in local tests. Exercise pure local logic with directly
constructed inputs; MUST NOT introduce dependency fixtures or mocks as
migration evidence or replace genuine dependency calls in recorded E2E.

## Metrics And Side Effects

Treat source metrics and required side effects as observable behavior. Validate
push metrics through recorder-owned dependency evidence when supported and pull
metrics through the target exporter or scrape surface. Do not synthesize
recorded metric payloads in the target harness.

When evidence cannot confirm an existing source metric or side effect, retain
an explicit unconfirmed status and report the missing recording or verification
step. Do not silently drop it because the HTTP response matches.

## Module And Dependency Design

Choose the smallest initial topology that fits the target repository and the
selected group. Keep transport, business orchestration, domain or wire models,
external adapters, startup wiring, and E2E support separated by dependency
direction. Test support must not enter the default runtime path.

Treat existing structure as evidence, not an unquestioned precedent. Refactor
the smallest relevant boundary when the migration would otherwise extend:

- a catch-all or incorrectly owned module;
- repeated prefix-sprawl that represents one implicit namespace;
- transport code containing persistence or external protocol details;
- shared infrastructure owned by one unrelated consumer;
- production code that imports replay or fixture support.

Use names that fit the target domain; do not prescribe example type, factory,
module, or directory names as standards. Keep bootstrap and library roots
focused on wiring and exports. Do not use source composition tricks as a
substitute for real language module boundaries.

Apply the target repository's code-size rules. Without a stronger rule, review
a new or heavily modified product file above 600 lines, split or justify it
before 800 lines, and do not complete with a product source file above 1000
lines without a user-approved exception. Generated code and protocol tables are
the normal exceptions.

## Schema And Runtime Values

For DB-backed behavior, map runtime decode types from explicit schema evidence,
not source-language model guesses. Accept recorder semantic column schema, a
user-provided schema, migrations, or another trusted schema source. Mark missing
or partial schema evidence explicitly and do not claim completion when it can
change runtime correctness.

Map dynamic values to their real product source: request/session context,
dependency state, time, generated ids, or explicit source-proven configuration.
Do not turn a value observed only in a recording into a product default.
Replay-only bind/ref, validation, and time rules remain owned by
`recorded-e2e-cases`.

## Structural Convergence

After the selected group first passes recorded E2E, reassess the implemented
responsibilities, names, visibility, dependency direction, runtime/test
separation, and file sizes. Refactor only the boundary introduced or expanded
by the current migration; keep unrelated legacy cleanup out of scope.

Rerun affected unit or component tests and the entire selected recorded case
set after every structural or behavior-affecting change. The latest successful
replay after the last such change is final evidence and is not counted as a
retry. If the review makes no such change after a successful replay, retain
that replay as final evidence instead of repeating it.

## Semantics Review

Before delivery, confirm:

- the source route or capability and all selected cases map to the implemented
  target behavior;
- normal startup uses genuine dependency paths and no recording-backed or
  fixture-backed dependency implementation exists;
- required metrics and side effects are implemented, verified, or explicitly
  blocked by missing evidence;
- dynamic values have real runtime sources;
- DB mappings use explicit schema evidence when applicable;
- local tests cover non-trivial logic without replacing recorded E2E;
- module ownership and runtime/test separation match the final code;
- every intended behavior change has explicit user approval;
- the full `recorded-e2e-cases` completion gate is satisfied from canonical
  artifacts.

Record an incomplete semantics or architecture status for every unresolved
item; a passing response alone cannot waive it.
