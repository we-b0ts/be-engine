# Repository Migration Memory

Use source-controlled repository memory to prevent later migration agents from
repeating expensive replay or implementation mistakes. It is human guidance,
not canonical replay evidence.

## Resolve The Documents

Before the first implementation or replay attempt, inspect `AGENTS.md` and
reuse its declared migration-notes and migration-changelog paths. When no
equivalent exists, use:

- `docs/migration-notes.md`
- `docs/migration-changelog.md`

Create any missing document at that point with only its title and a short
purpose statement. Do not reconstruct deleted per-API, per-case, or run history.

If `AGENTS.md` exists, keep its factual repository map linked to both documents
and state that notes are read before migration or replay. Do not create
`AGENTS.md` or change unrelated repository policy.

## Migration Notes

Read the notes before the first implementation or replay attempt and again
before retrying a familiar failure.

Upsert a lesson only after its fix passes verification and the lesson is useful
across multiple APIs, cases, or migration scopes. Repetition within one API,
case, run, or otherwise narrow scenario does not qualify. Update an existing
lesson instead of appending a duplicate. Use:

```markdown
## <stable problem title>

- Trigger: <recognizable symptom or context>
- Avoid: <ineffective action that must not be repeated>
- Resolved by: <verified diagnostic or fix>
```

Keep the document short and repository-specific. Do not copy protocol traces,
raw evidence, absolute machine paths, case or session ids, run counts,
transient error logs, secrets, or detailed repair history.

## Migration Changelog

Append one short entry for each delivered migration increment:

```markdown
- YYYY-MM-DD — `<scope>`: <brief behavior or architecture change>.
```

Do not add one entry per case, API retry, focused attempt, or full round. Omit
evidence statistics and root-cause detail; those belong in runner-generated
state and, when resolved and reusable, migration notes.

## Authority Boundary

Migration notes and changelog entries never prove replay success, consecutive
success, dependency coverage, or completion. Canonical runner state and
recorder-owned artifacts remain authoritative. Never hand-copy generated state
into either document.
