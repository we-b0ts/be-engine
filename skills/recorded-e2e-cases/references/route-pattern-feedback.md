# Replay-Time Route Pattern Feedback

Use this workflow only during replay discovery or replay follow-up. Recording
remains manually triggered and does not require source-repo scanning.
`traffic-replay` and all recording artifacts remain read-only.

For a collection or run with multiple canonical input directories, read
[case-grouping.md](case-grouping.md) first. Route registration analysis may
produce the candidate used by `traffic-case-group ensure` before business-code
analysis begins. A grouping result never waives the final managed pattern
plan/apply/replan gate below.

## Inputs

- published case, collection, rule, or run directory
- source repository and revision used to interpret API routes
- target repository recorder config, when it is source-controlled
- whether the supplied cases are a focused subset or the declared authoritative
  collection

Read the source framework's route registrations, including nested prefixes,
HTTP methods, `ANY` semantics, optional parameters, constraints, and handler
references. Prefer a framework route-list command or an existing AST route
extractor over text-only guessing.

## Case-To-Route Decision

For every published `request.json`, remove the query component for route
selection but preserve the complete recorded URI for replay. Match the HTTP
method first, then classify the path:

| Result | Feedback |
| --- | --- |
| Exact static route | `exact_static`; do not generate a pattern |
| One single-segment dynamic template | Continue to pattern safety checks |
| Optional, constrained, regex, or catch-all template | `unsupported`; do not generate |
| More than one template | `ambiguous`; do not guess |
| No template | `unmatched`; report source revision, prefix, or deleted-route mismatch |

An actual path that fails exact matching does not by itself prove that a
dynamic pattern is needed. Generate feedback only after a unique source route
template is established. Do not infer API identity from `uri-group`.

## Pattern Safety

Convert every supported dynamic path segment to one recorder `*`. Generate a
pattern only when all dynamic segments consume exactly one path segment.

Before accepting it:

1. Require at least one actual published case for the source route.
2. Check the generated path against every static source route, independent of
   method, because `case_path_patterns` groups by path only.
3. Mark it `dynamic_pattern_unsafe` and omit it if it can group a static API.
4. Report identical generated shapes owned by different methods or handlers;
   replay selection must still use method plus actual URI.
5. Sort and deduplicate accepted patterns deterministically.

## Target Config Update

Keep project-specific recorder config in the target repo. Restrict edits to an
explicit block such as:

```toml
# BEGIN AI-MANAGED CASE PATH PATTERNS
# source_revision = "<revision>"
case_path_patterns = [
  "/api/example/*",
]
# END AI-MANAGED CASE PATH PATTERNS
```

- Require `traffic-recorder-config` from `PATH`. Never edit the target TOML
  directly and never create the config or managed markers on the target's
  behalf. If the command is unavailable or rejects an existing managed block,
  report `blocked` with the confirmed patterns and stop the config-update step.
  If the source repo or managed target config is absent, record exactly
  `not_applicable_missing_source_repo` or
  `not_applicable_missing_managed_config`; generic `not-applicable` is invalid.
- Preview feedback first. The plan command is mandatory whenever the source
  repo and managed target config exist, including when no pattern or no diff is
  expected. A focused plan with no candidate patterns omits `--pattern` and
  MUST return `no_candidates: true`, `changed: false`, and an empty diff.
  Persist its JSON output as evidence. Supply the target config, rule
  name, source revision, case source, authority mode, and every accepted pattern:

```bash
traffic-recorder-config case-path-patterns plan \
  --config path/to/recorder.toml \
  --rule record-api \
  --authority focused \
  --source-revision <revision> \
  --case-source path/to/cases \
  --pattern '/api/example/*' \
  --format json
```

- Inspect `added`, `removed`, and `diff`. For focused feedback, require
  `removed` to be empty. When the reviewed plan contains a confirmed safe diff,
  running the same command with `apply` is mandatory; a planned-but-unapplied
  diff is incomplete. Persist the JSON apply report, then rerun and persist
  `plan` with the same inputs; its final `diff` MUST be empty. Record
  `confirmed_no_change` only when the initial plan has no diff, and `applied`
  only after this apply-and-replan verification closes the loop.
- For an authoritative collection, pass `--authority authoritative`. If the
  reviewed plan removes patterns, the apply command must also include
  `--allow-delete`. Never use that flag for focused feedback.
- For a focused or partial case source, preserve existing entries and add only
  newly confirmed safe patterns.
- Rebuild or delete entries only when the case source is declared authoritative
  by the target workflow.
- Never copy recorded parameter values into product config or product code.
- The CLI must validate the complete TOML, preserve text outside the managed
  block, and show the config diff. Show that diff to the user.
- Do not move or rename existing case directories; new patterns affect only
  future manual recordings.

Record `recorder_config`, source revision, case source, authority mode, counts
for each decision status, and `route_pattern_feedback_status` in the target
migration state when that file exists.
