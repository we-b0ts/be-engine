# SSE response diagnostics

Use `backend-rewrite --target-root <target> evidence --api '<route>'`, then
execute its returned `case_response_differences` query. Each SSE frame
difference includes `interaction_diagnosis` with the expected and actual event
names, JSON `type`, payload and raw JSON field differences. Values returned by
the API are shown directly without redaction. A length difference also includes
the ordered event inventory, making missing or extra event types visible.

Both diagnostic event indices and event counts exclude heartbeat frames, just
like response assertion. The original `sequence` remains available as an
observation locator; different Source and Target sequence numbers alone do not
prove a response mismatch.

Interaction headers and payloads remain encrypted in the original recording and
actual-response artifacts. The query authenticates and decrypts each response
once per page in memory. Plaintext payloads are not added to saved assertion
reports, workflow state or the ordinary public diagnosis. Unreadable or
unauthenticated evidence is `unavailable`, independently of a missing frame or
a present JSON `null`.

Each value preview is limited to 4096 UTF-8 bytes. Event inventories include at
most 128 frames, with an explicit omitted count. Each frame includes at most 20
raw JSON differences, with an explicit truncation flag and bounded traversal.
Continue through the returned page command for more failed frames.

Raw JSON differences precede value contracts: an authorized generated ID or
timestamp may still appear there. They explain the observed bytes and do not
replace the assertion outcome or authorize a new rule. Source proof and the
ordinary rule plan/apply workflow remain required.
