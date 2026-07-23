---
name: e2e-rewrite-migration
description: Use when rewriting or migrating one API, scheduled job, worker, or service capability from a local source repository into another language using local recorded E2E cases or recordings fetched from a remote task-service IPv4 address as the behavior contract. Requires a source repo, target repo or current workspace, target language, published cases, real dependency paths, a standard project CLI facade, final E2E evidence, and PR delivery.
---

# E2E Rewrite Migration

Rewrite behavior, not source text. Complete one capability only when its entire
selected case set, genuine dependency path, normal startup, target quality
checks, focused commit, pushed branch, and PR are verified from the final tree.

## Mandatory Semantics

Interpret `MUST`, `MUST NOT`, `REQUIRED`, and `BLOCKED` literally. Completion is
an AND gate. Partial implementation may be handed off, but remains `incomplete`
or `blocked`. Target helpers and migration ledgers are never canonical proof.

A blocker prevents a completion claim, but does not prevent incremental
delivery. Commit, push, and create a PR for useful focused changes while
accurately reporting unresolved blockers.

Use `recorded-e2e-cases` as the sole owner of case grouping, managed replay,
dependency coverage, response assertions, replay policy, aggregate reports,
route-pattern feedback, verified excludes, and their completion artifacts. Do
not duplicate or weaken that contract here or in the target repository.
Before prepare or replay, load `recorded-e2e-cases` and follow its reference
routing. If the companion skill is unavailable or incompatible, stop as
`blocked` and report the exact issue.

Generate stable project metadata in `.traffic-e2e/e2e.yaml` with
`traffic-e2e init`; if the required project CLI, replay policy, or PR base
cannot be confirmed, ask the user instead of guessing. The generated config
must be complete and its PR base resolvable before prepare or replay. Treat
runner-generated progress and detailed evidence according to
[e2e-run-state.md](references/e2e-run-state.md). MUST NOT stage, commit, or
force-add `.traffic-e2e/local/`; ignoring it never waives evidence.

## Required Inputs

- local source repository path;
- target repository path, or the current workspace;
- target language;
- either a local case source containing at least one published recorded case, or
  one remote task-service IPv4 address from which to select one recording.

Stop and request a missing source path, target language, or case-source mode
before implementation. In remote mode, require only the IPv4 address; derive
the Admin API as `http://<ipv4>:9090` and use the bundled task helper. Source
tests may supplement but never replace recordings.

## Reference Routing

- Read the language reference only for the selected language, such as
  [rust.md](references/rust.md).
- Read [delivery.md](references/delivery.md) before choosing a branch and again
  before commit, push, and PR.
- Read [target-runtime.md](references/target-runtime.md) before changing startup,
  dependency wiring, config, commands, diagnostics, or `AGENTS.md`.
- Read [implementation-quality.md](references/implementation-quality.md) after
  grouping and again after the selected group first passes.
- Read [e2e-run-state.md](references/e2e-run-state.md) before reading,
  delivering, or diagnosing runner-generated state.
- Read [repository-memory.md](references/repository-memory.md) before the first
  implementation or replay attempt and again before delivery.
- Read [remote-case-source.md](references/remote-case-source.md) when the user
  supplies a remote IPv4 address instead of a local case source.
- Read [logging.md](references/logging.md) only when runnable-service diagnostics
  are absent or changed by the current migration.

## Workflow

1. Resolve the case-source mode. For a local case source, preserve the existing
   path exactly. For a remote IPv4 address, follow `remote-case-source.md`,
   invoke this skill's `scripts/pluto-task.sh` by absolute path, and freeze the
   remote artifact list. Inspect target instructions and conventions, source
   route registrations or job wiring, normal startup, Git state, and declared
   repository migration notes. Before generating migration state, require
   `.traffic-e2e/local/`, `.traffic-e2e/.env`, and the target's local
   application environment file in the target root `.gitignore`, then verify
   them with `git check-ignore`. Resolve the PR base and pass it to
   `traffic-e2e init`; do not begin prepare, status inspection, or replay with
   missing or incomplete stable project configuration. In remote mode, then
   materialize candidates in ascending order and select the oldest clean
   recording whose canonical case sources do not all have successful runner
   state. Select at most one recording per invocation and inspect its resolved
   recordings before implementation.
2. Use `traffic-e2e prepare` through `recorded-e2e-cases` to select exactly
   one canonical API/function group. If no API is named, select one unprocessed
   complete group from the available source, recording, dependency, and replay
   evidence, state the selection rationale, and proceed one group at a time. Do
   not infer priority from HTTP method or directory order. Resolve dynamic
   patterns before implementation.
3. Resolve `pr_base` from user or repository evidence. It is only the PR
   target. Perform migration work on a named feature branch.
4. Inspect only the selected source capability. Implement idiomatic target
   behavior with normal startup and the same genuine dependency interfaces,
   production adapters, and protocol clients used during recorded E2E.
   Materialize the required normal and E2E runtime configuration according to
   `target-runtime.md`; do not leave a committed environment template
   disconnected from target config loading or require a person to reconstruct
   source-proven dependency configuration by hand.
   Provide the standard `scripts/<project>-cli` facade and delegate its commands
   to the target repository's native build and test tools.
5. Use the replay-policy version-two facade contract for new migrations: the
   target reads `request.json`, exercises genuine runtime behavior, and writes
   the runner-named actual-response artifact. It MUST NOT read
   `expected-response.json`; the runner alone owns final response assertions.
   Target product code, E2E code, test support, commands, and normal config MUST
   NOT read `dependencies.jsonl` or dependency fixtures to produce dependency
   results. The migration agent may inspect recorded dependency evidence
   offline only under the configuration-provenance rules in
   `target-runtime.md`; it MUST NOT infer provenance from a downstream request
   or materialize a value that the source obtains from a runtime dependency.
6. Use `traffic-e2e run-api` for the selected API's migrate/fix loop. Fix
   product code only after replay evidence proves a real behavior defect.
   Run it only until the current complete API group passes, then stop. Do not
   repeat a successful case source to advance verification or manually
   reconstruct runner state. Let `recorded-e2e-cases` own aggregation, progress,
   and verified-exclude updates. After a fixed and verified problem meets the
   cross-scope reuse rule, upsert the concise repository migration lesson
   required by `repository-memory.md`.
7. After the group first passes, perform structural convergence and migration
   semantics review. If that review changes behavior, structure, dependency
   wiring, replay policy, or assertions, rerun the affected focused group after
   the last such change. If the review makes no such change, the existing
   successful focused attempt is the final focused evidence; do not repeat it
   merely to create a separate final verification. Do not start a full round
   while any focused group still fails. After every published case is prepared
   and migrated, follow the `recorded-e2e-cases` regression gate to retain the
   grouped evidence or run `traffic-e2e run`. A non-successful full round
   returns to focused repair.
   Run normal-startup smoke and target-required quality checks from the final
   tree.
8. Maintain the concise repository migration notes and changelog defined by
   `repository-memory.md`. Update only factual `AGENTS.md` map links made
   inaccurate or materially incomplete by the current change. Do not create the
   file or change repository policy or completion gates without explicit user
   authorization.
9. Commit only intended changes, including one concise changelog entry for the
   delivered migration increment, push the feature branch, create a PR to the
   configured `pr_base`, and verify the remote state. Let `traffic-e2e` update
   the runner-owned run index; record its exact canonical artifact paths and
   identifiers in the final handoff without editing generated state. Exclude all
   files under `.traffic-e2e/local/` from staging and delivery. Do not skip
   incremental delivery solely because the migration remains `incomplete` or
   `blocked`.

Continue the implementation/replay loop while each cycle adds evidence or fixes
a distinct evidenced defect. If the same root cause repeats for three
consecutive cycles without progress, stop that group as `blocked` or
`incomplete`. The latest successful replay performed after the last
behavior-affecting change is the final verification. Rerunning after such a
change is mandatory and is never counted as a retry; do not add another attempt
when no change follows the successful replay. Apply the resolved cross-scope
migration-notes rule to implementation, build, startup, test, and replay
failures.

## Non-Negotiable Completion Gate

MUST NOT claim a migration complete or delivered unless all items hold:

1. Target instructions are inspected. Record
   `repository_contract_status: agents_linked` when they declare the canonical
   skills, or `repository_contract_status: skill_managed` when they do not.
   Missing linkage is not a blocker; an unresolved conflicting or weakening
   instruction is `blocked_repository_contract`. The final factual repository
   map matches the implemented tree for the current scope. The migration-notes
   document was read, eligible cross-scope lessons were upserted without raw
   evidence, and the delivered increment has one concise changelog entry.
2. `.traffic-e2e/e2e.yaml` records the confirmed `pr_base`. Migration writes run
   on a named feature branch different from it, with unrelated changes
   preserved.
3. `recorded-e2e-cases` reports complete canonical grouping and immutable
   published recordings for the exact selected scope.
4. Normal runtime and recorded E2E use genuine dependency paths. No target-side
   recording-backed, fixture-backed, fake, or in-process dependency
   implementation reads recorder dependency data. The version-two target facade
   reads the request and writes only the runner-named actual response; it never
   reads the expected response. Required source-proven configuration is present
   through its authoritative target startup input or genuine runtime-dependency
   path, and the committed environment template contains no variable ignored
   by the target config path.
5. Source metrics and required side effects, explicit DB schema evidence when
   applicable, meaningful local tests, architecture review, structural
   convergence, and semantics review are complete. Any explicit blocker keeps
   the migration incomplete.
6. The full `recorded-e2e-cases` completion gate is satisfied after the last
   behavior-affecting change for every selected API, and its runner-owned
   progress reports the current logical run complete. A target facade or
   hand-maintained ledger cannot substitute for canonical final-state
   artifacts.
7. The standard project facade exposes working `start`, `stop`, `status`,
   `test`, `e2e --case-dir --actual-response`, and `check` commands for the
   runnable target. Normal-startup smoke and all target-required quality checks
   pass against the same final tree. Any later behavior, wiring, policy,
   assertion, or structural change invalidates earlier replay evidence.
8. A focused commit is pushed and a PR to `pr_base` is
   independently verified. The per-run state records, but does not manufacture,
   the exact evidence and delivery identifiers. `.traffic-e2e/local/` is ignored
   and contains no tracked or staged file.
9. For a remote case source, the final handoff records the remote IPv4 address,
   selected recording ID, frozen snapshot boundary, cache root, archive
   fingerprint, and every materialized canonical case source. The archive
   metadata and published-case count match the remote list entry, and the
   downloaded cache, helper exit status, or prose ledger is not used as replay
   completion evidence.

## Completion Blockers

- missing published cases, ambiguous grouping, or changed recordings;
- unreachable remote task service, invalid IPv4 input, unsafe or inconsistent
  downloaded archive, or missing bundled task-helper dependencies;
- incomplete or dirty `recorded-e2e-cases` evidence;
- target-side use of recorded dependency files or fixtures, or a version-two
  target facade that reads the expected response;
- no normal runnable startup or no genuine runtime dependency path;
- missing required local or E2E environment materialization, ignore rule, or
  loading path;
- missing or non-conforming `scripts/<project>-cli` core command facade;
- missing required schema, metrics, side effects, tests, convergence, or
  semantics evidence;
- unresolved target-instruction conflict or stale current-scope `AGENTS.md` map;
- an uncaptured eligible cross-scope migration lesson or missing
  delivered-increment changelog entry;
- final behavior-affecting change not replayed and rechecked;
- missing `.traffic-e2e/local/` ignore rule, or any tracked or staged local
  migration artifact;
- unresolved PR base, focused commit, push, or PR.

## Output

Use the migration status template only when this turn executes migration work,
hands off partial migration state, or makes a completion/delivery claim. Start
that output with exactly `complete`, `incomplete`, or `blocked`, then report the
selected scope, case source and canonical group, recorded-E2E artifact status,
startup/quality results, branch, commit, PR base/URL, run-state path, and exact
blockers. For remote mode, also report the IPv4 address, recording ID, snapshot
boundary, cache root, archive fingerprint, and resolved case sources. Include
the resolved project-facade path and commands. For analysis, review, or design
questions that do not execute a migration, answer normally without a synthetic
migration status.

Never use success wording while an applicable gate is missing.
