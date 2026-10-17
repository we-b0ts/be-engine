# Cross-case HTTP dependency replay

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v1` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


An API can reuse process-local state populated by an earlier API. For example,
one request obtains an OAuth client token and a later request reuses the cached
token. A fresh target replaying only the later API still emits the token fetch.
The `cross-case` rule makes the recorded initialization exchange available to
that real client without requiring the target to read fixtures or change its
startup behavior.

## Discovery and coordinator workflow

After a finalized Replay reports a case-scoped HTTP `unmatched_target`, the
API implementers query `evidence --api '<METHOD pattern>'` against the canonical
target root, then follow the returned overview to `dirty_clusters`.
The engine searches only that completed standard recording run, including the
other cases of the same API and cases of other APIs. It streams dependency
files and caches bounded candidate summaries next to the Replay report.
Changed report contents or source file identities invalidate the cache.
It does not serve an unmatched request during discovery.

`facts.cross_case_candidates` identifies the consumer case, source case, source
API path, selector, source record location, and request-match status. The public
evidence contains no request credentials, query values, or dependency responses.
`rule_hints` explains `cross-case`. Verified candidates expose a planner with
`kind: dependency_scope` and `capability: http_cross_case` in
`applicable_rule_planners`. Discovery also runs during response and Replay issues;
passing responses are not required. Old reports without a request fingerprint
can identify potential candidates but cannot authorize a plan: execute fresh
Replay first.

The worker inspects source and target initialization, sharing, expiry, refresh,
and required side effects. Same-URL traffic alone does not prove shared state.
The coordinator uses the current evidence ID and source-backed selector:

```bash
backend-rewrite --target-root /path/to/target dependency-rule plan http cross-case \
  --evidence-id <returned-evidence-id> \
  --rule-id erp-client-token \
  --host agent.erp.sample.test --port 80 \
  --method POST --path /api/oauth/client-token \
  --source-evidence 'wecode/service/erp_client.py:ErpClient._ensure_token stores a shared token until expiry'
```

This planner does not ask for `--ownership process-owned`: the request remains
business-triggered. Review the rule diff and affected source/consumer cases,
then run the returned `dependency-rule apply <plan-id>` and exact `next` command.
Apply revalidates current evidence and writes only verification policy. It
invalidates existing API verification and requires real Replay; it cannot clean
an old report whose target received a 502. Existing complete source exchanges
do not require fresh recording. The coordinator owns normal configuration Git
publication and the subsequent verification workflow.

## Policy

The generated `.traffic-e2e/verification.yaml` rule is:

```yaml
dependency_rules:
  - id: erp-client-token
    replay_scope: recording_run
    source_evidence: 'wecode/service/erp_client.py:ErpClient._ensure_token stores a shared token until expiry'
    protocol: http
    target:
      host: agent.erp.sample.test
      port: 80
    http:
      method: POST
      path: /api/oauth/client-token
```

`cross-case` is the capability name; `id` names one configured instance.
Omitting `replay_scope` preserves ordinary current-Case plus Global behavior.
`recording_run` requires an exact host, port, method, path, and source proof;
it forbids an API `case` selector and dynamic query fields. It is an HTTP-only
scope policy, separate from asynchronous process-owned recording rules.

## Runtime and matching

Before target startup, Replay loads its selected cases, ordinary Global data,
and HTTP exchanges selected by scope rules from the same completed recording.
Unselected cases' ordinary dependencies are not retained. Sharing is an
in-memory derived scope; recording JSONL and original ownership remain immutable.
Each physical exchange appears once, even when its original case is selected.
Shared inventory follows captured timestamps across APIs where available.

The consumer must still match HTTP/HTTPS, normalized host and port, method,
exact path, the complete query, and body. Query order is immaterial; names,
values, and duplicate counts stay exact even when ordinary Replay has global
query ignores. JSON objects use value equality; arrays retain order, and other
bodies (including form data) retain byte identity. Authorization, Cookie, and
Content-Type also participate in shared request identity. Rule files do not
contain their values. The private replay report carries only a SHA-256 request
fingerprint for subsequent diagnosis.

Only successful, complete, replayable exchanges may be shared. Each exchange
is consumed once per Replay session, with independent inventory in a new
session. Original cases do not demand a second consumption. Match/unused
reports retain `shared_origin` with the rule and original case; unmatched calls
remain dirty and shared unused exchanges remain Global diagnostics. This rule
does not synthesize responses, implement a token cache, renew token lifetimes,
or authorize unlimited reuse. Ordinary dependencies keep their case scope.
