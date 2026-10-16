# Coordinator Case Patterns

Use only for `case_pattern_identification_required`. Keep configuration
application here and delegate source route analysis.

`action.details.candidates` contains concrete APIs not covered by confirmed
Source registrations of the same HTTP method. Retain this complete
batch and its workflow/recording identity as one assignment.

Dispatch `api-implementer` with `task=route_analysis`, an assignment ID, the
source repository location, and the exact candidate batch. This read-only task
uses its route-analysis entrypoint. Do not call the engine's `worker confirm`
for this task or invent an API issue; it has no implementation-worker binding.
Retain its actual runtime handle and resume that task for missing source proof.

Require the same assignment and complete input batch in the result, plus one
JSON array of confirmed `METHOD path-or-pattern` registrations and source references. Re-read global status before applying.
If the candidate batch or recording changed, reject the stale result and follow
the current action. Do not merge partial or conflicting analyses yourself.

Set the environment variable named by
`action.details.pattern_input.environment_variable` to the complete returned
JSON array. Include every static route explicitly, for example
`["GET /items/*", "POST /items/upload"]`; an empty array does not confirm
uncovered candidates. Execute the exact
`action.commands.apply` argv without adding pattern arguments.

Apply updates the managed source traffic policy and derived catalog/inventory;
it does not edit or move recorded cases. Follow the returned `advance_required`.

Registration is method-specific. Existing `GET /items/*` covers a later
`GET /items/upload` observation without another confirmation, unless that GET
static Source was already registered. It cannot cover POST. Confirmed static
Sources survive later wildcard registrations; equal templates across methods
share one API work item and retain separate verification records. Do not infer
Source registration from a recorded `api_pattern` or a methodless path hint.
