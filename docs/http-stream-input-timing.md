# HTTP stream inputs and dependency timing

Fast Replay of an SSE/NDJSON case with one independent absolute client-close
input shares one Source time mapping between that input and its successful,
complete HTTP dependency streams. Request, header, chunk, EOF and close offsets
are ordered once at input admission. Each adjacent gap is capped by the existing
stream interval cap. Ordinary cases retain their existing timing path.

The close cannot become ready until the mapped close time and every selected
pre-close stream prefix has actually crossed its HTTP writer. A dependency's
post-close chunks and EOF remain blocked until the primary driver has executed
its real dedicated-transport cancellation and acknowledged that action over the
private control channel. This is transport-input acknowledgement, not proof that
the application has completed cancellation handling.

Waiting never holds the Replay state lock or the control server. Each stream
retains a prepared metadata schedule and its next-chunk cursor; delivery does
not rescan Source records, parse business messages or inspect expected outputs.
Case admission identity and clock epoch protect close queries. Abandoning a Case
fails blocked delivery instead of releasing future Source bytes.

For older response-adopted HTTP captures whose request timestamp was written at
response headers, the independently recorded admission timestamp supplies the
earlier input origin. New captures preserve the original HTTP request timestamp
when adopting the response into stream ownership. A mismatched admission Case,
missing dependency request clock, invalid stream timing or unsupported partial
stream cannot authorize this shared fast path.

For an unfinished response with a real primary client cancellation, an HTTP
dependency may independently close before its recorded proxy EOF. Acceptance
requires actual FIN/RST after the primary close and a flushed pre-close input
prefix. BodyDrop alone, early dependency cancellation and engine cleanup remain
failures. The report retains `cancelled_http_streams`, the real termination and
queued chunk counts, with `recorded_eof_delivered: false`. The exchange remains
separate from complete Source consumption.

The same actual primary cancellation automatically permits tail-length
differences in temporary Redis streaming caches. An existing APPEND-stream
contract, an initially empty value, successful key-local expiry and absence of
read/reset fences must prove eligibility. Exact Source APPEND bytes must be a
prefix of a unique stream of string fields in the authenticated pre-close
primary response. Target APPENDs must follow that same continuous byte prefix;
they can stop earlier or extend up to the primary response's finite content
ceiling. APPEND returns the actual Target cumulative length. A complete response
assertion is still required for the case to pass. There is no Target option.

`redis.allowed_cancelled_cache_tails` reports Source and Target lengths, missing
or additional bytes, and partially or fully omitted Source exchanges. Omitted
records retain their real native delivery status. These differences are accepted
because business flush timers run independently of accelerated stream timing;
this tradeoff can conceal a missing final cache flush in a cancelled request.
Normal completed requests, nonexpiring values, observed/reset state and other
dependency protocols retain their strict contracts. Candidate derivation is
bounded and performed once, outside input execution and the stream delivery loop.

Standalone `traffic-e2e prepare`, `run-api` and `run` validate the current
checkout, including the configured delivery base branch. Their execution does
not edit Target implementation or enter a rewrite workflow. Managed
backend-rewrite preparation and Replay retain their feature-branch checks.

An opt-in ignored engine regression can replay a real recording against an
existing immutable production image when the current Target checkout has moved
on. `recorded_http_close_on_pinned_target` requires `TRAFFIC_E2E_TEST_TARGET_ROOT`,
`TRAFFIC_E2E_TEST_CASE_SOURCE`, `TRAFFIC_E2E_TEST_RUN_KEY`,
`TRAFFIC_E2E_TEST_API`, `TRAFFIC_E2E_TEST_RESULT_PATH`,
`TRAFFIC_E2E_TEST_ENGINE_BINARY` and `TRAFFIC_E2E_TEST_TARGET_IMAGE`.
Prepare that standalone run key normally first. The image must be a locally
available `sha256:` id, not a mutable tag. Run only this ignored test with one
test thread. These test-only adapters still execute the normal isolated Target,
real dependency Replay and assertions. The result applies to that image, not to
the current Target source candidate; keep its standalone run key separate from
managed rewrite evidence.
