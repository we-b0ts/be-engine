# Traffic E2E Replay-Time Route Pattern Feedback

Use this workflow only during replay discovery or replay follow-up. Recording
remains manually triggered and does not require source-repo scanning.
`traffic-e2e replay` and all recording artifacts remain read-only.

For a collection or run with multiple canonical input directories, apply the
case-grouping contract loaded from the main skill first. Route registration
analysis may produce the candidate used by `traffic-e2e prepare` before
business-code analysis begins. A grouping result never waives the final managed
pattern plan/apply/replan gate below.

## Inputs

- published case, collection, rule, or run directory
- source repository and revision used to interpret API routes
- target repository recorder config, when it is source-controlled
- whether the supplied cases are focused or collection-wide feedback; this
  scope is metadata only and never authorizes deletion by omission

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
| One single-segment dynamic or confirmed catch-all template | Continue to pattern safety checks |
| Optional, constrained, or regex template | `unsupported`; do not generate |
| More than one template | `ambiguous`; do not guess |
| No template | `unmatched`; report source revision, prefix, or deleted-route mismatch |

An actual path that fails exact matching does not by itself prove that a
dynamic pattern is needed. Generate feedback only after a unique source route
template is established. Do not infer API identity from `uri-group`.

## Pattern Safety

Recorder `*` matches exactly one non-empty path segment. A final recorder `**`
is a catch-all matching one or more remaining path segments. `**` must occupy a
complete segment and may appear only at the end. Determine the source route's
parameter semantics before selecting either recorder wildcard.

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

- Recording limits are target-owned and independent from route feedback.
  `http_gateway.case_limits.default` applies per resolved case pattern, while
  exact keys under `http_gateway.case_limits.overrides` may set different
  limits. Do not add or raise these limits merely to make replay discovery
  record more cases. Pattern feedback must preserve existing limit settings.
- Require `traffic-e2e` from `PATH`. Never edit the target TOML
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
traffic-e2e diagnose recorder-config \
  --config path/to/recorder.toml \
  case-path-patterns plan \
  --rule record-api \
  --authority focused \
  --source-revision <revision> \
  --case-source path/to/cases \
  --pattern '/api/example/*' \
  --format json
```

- Inspect `added`, `removed`, and `diff`. Normal feedback under every authority
  mode is add-only: preserve every existing entry and add only newly confirmed
  safe patterns. A full run, all published cases in one case source, a changed
  inventory, or the absence of a current matching case never proves an existing
  pattern is obsolete.
- Delete only to correct a specifically named pattern previously generated
  inside the `AI-MANAGED CASE PATH PATTERNS` block. First inspect the current
  source route registration and prove that the existing pattern itself is
  incorrect, ambiguous, or unsupported. Never treat a route or case missing
  from the current recording as correction evidence.
- For a correction plan, pass each exact existing pattern with
  `--remove-incorrect-pattern` and provide single-line source file, revision,
  and route evidence with `--correction-evidence`. The tool must reject an
  implicit removal or correction evidence without a named removal. On the
  initial plan, require every named correction to appear in `removed`; an
  already absent name is a no-op and must not authorize apply. Show the deletion
  diff to the user before applying it. Apply only when the user requested that
  correction or explicitly approved the shown diff, and include
  `--allow-delete`.
- When a reviewed plan contains a confirmed safe addition or approved
  correction, running the same command with `apply` is mandatory. Persist the
  JSON apply report, then rerun and persist `plan` with the same inputs. Its
  final `diff` MUST be empty; a corrected pattern appears in
  `corrections_already_absent`. Record `confirmed_no_change` only when the
  initial plan has no diff, and `applied` only after this apply-and-replan
  verification closes the loop.
- Never copy recorded parameter values into product config or product code.
- The CLI must validate the complete TOML, preserve text outside the managed
  block, and show the config diff. Show that diff to the user.
- Do not move or rename existing case directories; new patterns affect only
  future manual recordings.

Record `recorder_config`, source revision, case source, authority mode, counts
for each decision status, correction evidence when applicable, and
`route_pattern_feedback_status` in the target traffic E2E state when that file
exists.
