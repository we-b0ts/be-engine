# Primary HTTP SSE recording and replay

SSE uses the shared interaction lifecycle described in
[streaming and Socket.IO](interaction-recording.md). Enable
`recorder.http_gateway.record_streaming` to forward and record complete logical
SSE events incrementally. Comments are protocol heartbeat observations and do
not extend the default 10-second business idle.

Finite responses complete at HTTP EOF. A long-lived response needs an explicit
terminal event/text/JSON profile; pending requests time out instead of passing
because no data arrived. The default activity limit is 10 minutes. Closing the
response and finalizing the case have a 60-second hard limit; dependency
attribution uses the existing recording post-response window (default 100 ms),
then drains accepted in-flight exchanges (default timeout 5000 ms). New traffic
does not restart that window. Replay retains its configured case-end window
(default 10 ms) and original dependency delivery ownership.

Normal EOF or terminal/idle completion closes the response while Source and
Target continue serving subsequent cases. Longer background work uses existing
process-owned/API-origin policy with its source and identity proof; it does not
require stopping either process or adding a streaming-specific quiet period.
See [case closure and background work](interaction-recording.md#closing-a-case-and-background-work).

The former `sse_observation` contract with a fixed 50 ms observation window is
retired. Existing evidence carrying that metadata is rejected with an explicit
instruction to record again. Recordings are never rewritten or interpreted as
having observed a different duration. Ordinary HTTP cases keep their existing
behavior.

SSE is response streaming over HTTP/1.1 in this implementation. HTTP request
streaming uploads, HTTP/2 bidirectional streaming and grouping multiple independent
HTTP requests into an MCP session are outside this adapter's contract.
