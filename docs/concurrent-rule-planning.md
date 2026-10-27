# Concurrent rule planning

The API implementer supplies a self-contained rule and its Source conclusions.
The rewrite coordinator calls `rule plan`, reviews the expanded rule, evidence
coverage and diff, then explicitly calls `rule apply <plan-id>`. These remain
separate decisions. Planning and application never certify a genuine Replay pass.

## Planning while Replay runs

A plan may use a different API's completed, published focused attempt while a
Replay operation is running. The selected route's reserved or active Replay,
including another method of that route, blocks planning against its old attempt.
Ambiguous active-run identity also blocks evidence access. An active full run
cannot supply fallback full-run evidence.

Plan validation retains complete Source scope, exact selected case membership,
independent Target witnesses, protected artifacts, key/schema identities and
policy freshness. Growing the shared prepared index for an unrelated API does
not invalidate a plan: the selected group's membership is checked semantically.

New resource rules omit `match.api`. Their Source coverage includes every
matching case in the recording, regardless of the issue's API. Preflight uses
each affected API's own completed execution and protected clocks; missing Target
evidence retains an explicit fresh-Replay obligation. An active affected API
blocks access to its old evidence. Unrelated API progress does not block resource
planning. Source inventory changes, relevant prepared membership changes, a
foreign execution replacement or newly available Target evidence invalidate the
plan. Apply and recovery recheck these identities. Applying a changed policy
invalidates earlier API verification fingerprints so they require revalidation.

A published foreign attempt interrupted before Replay finalization, or retaining
incomplete aggregate coverage, supplies no Target validation to a resource plan.
Its complete immutable Source cases are still validated and retain a fresh-Replay
obligation. The plan freezes that attempt's state, so replacing even an
unfinished attempt invalidates it. Active attempts and missing artifacts from a
claimed complete execution remain errors. The primary planning attempt must
still contain complete, finalized Replay and runner-owned assertions; use a
completed focused attempt as the anchor for a resource/global rule.

Interrupted diagnostic snapshots may contain sealed payload observations,
aggregate counts and assertions for executed cases. Sealed payload coverage is
not execution completion: an unfinalized or incomplete primary attempt still
cannot anchor a rule plan. Diagnose that attempt and run fresh Replay, or use a
completed focused anchor for a resource/global rule.

MySQL global formats reuse native request-clock and SQL-shape candidate
selection. A different UPDATE column set is an unpaired search edge, leaving
Source proof and a fresh-Replay obligation; it is not a passed Target witness.
Same-shape requests still validate all selected formats and exact unselected
values, and a valid pair cannot hide another invalid Target observation.

Each API has a planning/application lock. Different APIs can plan concurrently.
Plans publish through a separate atomic event file instead of replacing the
coordinator's in-memory workflow snapshot. Workflow loads and snapshot saves
fold in newer plan events. Publication rechecks workflow, recording, selected
API issue/attempt/inventory and policy identity. A concurrent transition cannot
silently retarget a proposal or discard an accepted plan.

## Applying at an idle boundary

An application attempted during Replay returns a successful command response
with `traffic_e2e_report.status: wait_required`, `applied: false`, `queued: false`,
the current blocking action and an exact retry command. The top-level
`next_command` requests status. Keep the reviewed plan; do not poll Apply in a
loop. Nothing is automatically scheduled to write the policy.

After every completed Replay step, both passing and failing, the engine reloads
pending plans before deciding whether to continue `auto_next`. A valid pending
plan produces `plan_apply_required` ahead of implementation/integration or the
next Replay. This gate also applies to explicit API selection and revalidation.
Current evidence and failure/implementation issues are preserved. A stale plan
instead offers its recovery command; valid plans are considered first.

Publication and the next Replay reservation share a short lock, so a plan
already published at that scheduling boundary cannot be bypassed. Expensive
validation is outside that lock. Running Replay is never preempted. Abnormal
operations and stale leases require recovery before applying rules.

The coordinator reviews and applies the returned plan, then follows `next`.
Application revalidates the exact plan, retains the existing durable write
intent/rollback protocol and requests fresh verification or recording as
appropriate. Existing configuration commit gates remain in force. A rule does
not erase a failing API's implementation issue or turn its old result into a pass.

If a newer attempt replaced a plan's issue, recovery retires the old plan while
preserving the newer result and issue. Concurrent changes to the policy still
invalidate plans based on its previous bytes; coordinators follow recovery and
fresh-evidence guidance rather than automatically rebasing reviewed rules.
