# API Implementer Route Analysis

Use only for an explicit `api-implementer` assignment with `task=route_analysis`.
Read source routes; do not edit code or invoke workflow commands.

## Input

Require the assignment ID, source repository location, and either the exact
candidate batch or the exact API needing a complete source registration route.
Return missing inputs without inventing an issue, worker dispatch, or API binding.

## Analyze

Inspect route declarations and every mount prefix in the assigned source.
For each dynamic candidate, preserve literal segments and replace only variable
whole segments with `*`. Use `**` only as the final segment when the source
itself defines a multi-segment catch-all. Include static paths explicitly and retain the Source HTTP method.

For a requested source route, return the complete registration path with every
mount prefix and the original named parameters. Do not return a local decorator
path when its router is mounted below another prefix.

## Output

Echo the assignment ID and exact input batch/API. Return narrow source
file/symbol references with:

- one complete JSON array of `METHOD path-or-pattern` registrations for a batch,
  including static routes, for example `["GET /items/*", "POST /items/upload"]`;
- or the exact complete source registration route for the requested API.

Report unresolved candidates and their missing proof explicitly. Do not guess
patterns or HTTP methods from example request values. Match each candidate
method to the actual Source declaration. Do not query `evidence --api` for this
analysis-only assignment, apply configuration, or continue into implementation.
