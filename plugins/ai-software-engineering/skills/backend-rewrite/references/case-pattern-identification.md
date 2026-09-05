# Case Pattern Identification

Read this guide only for `case_pattern_identification_required`. The main
orchestrator owns this low-frequency configuration action; API and
process-output workers never receive it.

`action.details.candidates` contains only concrete APIs that are absent from
the persistent historical API catalog and are not covered by current
`case_path_patterns`. Treat the full list as one batch. Do not request traffic
evidence or source-revision metadata.

For every genuinely dynamic route:

- preserve literal path segments;
- replace only variable whole segments with `*`; and
- use `**` only as the final segment when the source route itself defines a
  multi-segment catch-all.

Static paths need no pattern. Set the environment variable named by
`action.details.pattern_input.environment_variable` to one complete JSON array
containing only the identified path patterns. Use `[]` when every candidate is
static. Execute the exact `action.commands.apply` argv without adding pattern
arguments.

Applying the batch updates the coordinator-managed source traffic policy and
recanonicalizes the historical API catalog and current derived inventory. It
does not edit prior `request.json` files or move recorded case directories.
Execute the returned `advance_required` command to continue normal inventory
installation.
