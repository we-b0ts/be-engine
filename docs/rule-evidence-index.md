# Indexed Source proof for rule transactions

Rule planning separates the complete immutable recording inventory from the
API groups selected for execution. A skipped or not-yet-prepared API remains in
Source evidence; it does not prevent another fully prepared API from planning.
The selected API must still contain every published matching case, and the
finalized attempt must cover that exact method/group inventory. Full-run
execution retains its own complete-group requirement.

## Recording preparation

Recorder builds dependency locations and SHA256 values while producing its
Case summaries and paged Global index. Case fragments also retain compact
Source-proof selectors for every dependency exchange, with original byte ranges
and record checksums. Large SQL/argument payloads are removed from these
selectors and marked as requiring an original read; uncertainty never proves
that a record is outside a rule.
Case proof selectors omit request headers, URL query values and response headers other than
content type. Remaining SQL/key selector data stays in private evidence storage;
public plans and hints never expose its payloads or signing inputs.

After final manifest publication and ownership assignment, Recorder seals
`.source-proof-index.json`. It contains the complete list and content identities
of published requests, expected responses, Case dependencies and Global
dependencies. Dependency hashes reuse already sealed indexes; remaining file
hashes are computed once with a bounded buffer. Expected responses remain
assertion oracles and never become Target inputs.

Prewarm failure is explicit in Recorder logs and does not change the recording
completion contract. Existing recordings without this catalog build it in the
private dependency-index cache on first use. Missing protocol indexes are
derived once from original evidence. Later rule plans reuse them. A different
recording batch receives its own inventory; it cannot reuse another run's
membership or observations.

## Plan and apply

The evidence owner checks the complete file membership and each file's size,
device/inode, nanosecond modification time and change time. The frozen catalog
binds these identities and content hashes. An added, deleted, replaced or
modified Source member invalidates a saved plan, including changes outside the
active API. Descriptor and signing-key witnesses retain their separate frozen
content checks.

Protocol owners query the indexes for all applicable records and read their
original bytes through the checksum-verifying reader. Source classification and
capture use compact metadata to exclude unrelated payloads. HTTP/Redis finite
sharing retains exact request identity, complete successful responses,
Source lifetime proof and finite consumption. A bounded candidate preview does
not bound validation: every matching record is checked, including candidates
beyond the preview. Index metadata never grants a matching or exemption rule.

Before apply, the engine checks the frozen catalog and files again, re-enumerates
Source membership and revalidates relevant original records. A changed derived
catalog, Source inventory, key, policy, engine or Target identity requires fresh
planning. Source-only validation never satisfies an independent Target witness
or genuine Replay obligation.

## Resource bounds

There is no 512 MiB limit on the sum of an entire recording's files. Hashing uses
a bounded buffer; Source classification/capture retain their 8 MiB record bound,
and sharing retains protocol-owned bounds and a bounded byte cache. File/record counts and format-specific limits remain
explicit. Large descriptor inventories are hashed independently; they cannot
silently omit members to fit a preview or memory budget.

Normal warm-plan work scales with inventory metadata plus the records required
by the rule. A rule intentionally covering most of a recording still validates
that complete scope. No optimization removes original recording data, alters
comparison semantics, or changes the project's regression skip configuration.

Regression tests cover a recording larger than 512 MiB with zero original
payload reads on warm catalog lookup, same-size mutations, missing and added
members, corrupt derived catalogs, record-checksum failures, 65 matching
exchanges beyond the candidate preview, and independent plan/apply guards.
