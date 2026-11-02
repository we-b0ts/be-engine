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

New interaction event data, incomplete frames, close reasons, request bodies,
URIs and response headers are stored without additional encryption in the
original recording and actual-response artifacts. This applies to Socket.IO,
WebSocket, SSE, NDJSON and raw streams. Binary messages retain their explicit
Base64 encoding. Only request headers listed in the project's
`recorder.recording.encrypt_request_headers` are encrypted, including headers
on a Socket.IO WebSocket upgrade. No private interaction envelope is added.
Historical version 1 encrypted interactions and version 2 SSE artifacts remain
readable without rewriting recordings. The query loads each response once per
page and decrypts historical private fields in memory. Payloads are not added to saved assertion
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
