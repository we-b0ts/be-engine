# API Implementer Process-Output Diagnosis

Read after [API Implementer Diagnosis](api-implementer-diagnosis.md) only for
`work_scope.kind=process_output`. The common work-scope and handoff
contracts still apply.

## Process-Output Issues

For `work_scope.kind=process_output`, query `evidence --process-output <id>`
against the assigned canonical root after dispatch confirmation. The overview
has no API `queries`. Start from `facts.issue.comparison_observation`, which
identifies the process-output ID, configured path, classification, comparison contract, and source/target
presence. Do not look for an API representative or `case_dir`, execute API
evidence queries, inspect dependency traffic, or invent a recording operation.

For a missing metrics profile with source present and target absent, trace the
ordinary product output path:

```text
configured output -> component loading -> initialization -> startup -> write
or flush -> observation timing -> shutdown
```

Confirm the configured path and source-side presence from the overview, then
inspect the corresponding source and target component wiring.

When `comparison_observation.rule_candidate` names
`allow_target_missing`, first inspect the source startup/configuration and
indirect-emitter paths described by the candidate. The candidate is not an
allowance. Return its `metric`, a dependency path ordered from the direct
dependency to the indirect emitter, and one structured `emitter_evidence`
object only when source code does not start the interaction and the interaction
does not affect source behavior. `emitter_evidence.inspected_paths` must name
the source and dependency source paths actually read, and `description` must
explain why the indirect dependency emits independently without affecting
source behavior. Do not include boolean eligibility fields. If either
eligibility condition is not proven, do not return rule inputs; repair the
target's normal startup, configuration, output creation, flush, or shutdown
behavior.

Do not create a replay-only file, copy a recorded output into the target, or
make target code read engine artifacts.

For a target repair, return the exact work scope and issue ID, proven cause,
changed files and shared impact, patch or commit, local test results, original
dispatch identity, and unresolved risks. For an eligible rule candidate,
return the same work scope, issue and original dispatch identities plus the three
requested rule inputs and unresolved risks; no target patch or local test is
required. Do not apply rules or run process-output comparison yourself.
