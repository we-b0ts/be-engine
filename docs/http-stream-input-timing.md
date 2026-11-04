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

The scheduling change does not truncate a recorded complete dependency response,
turn Target BodyDrop into successful EOF, waive APPEND bytes, or manufacture
termination evidence. An old capture may still need independent native
termination/consumption evidence when its proxy completed an upstream response
that Source business code did not consume. Actual Replay retains that failure.

Standalone `traffic-e2e prepare`, `run-api` and `run` validate the current
checkout, including the configured delivery base branch. Their execution does
not edit Target implementation or enter a rewrite workflow. Managed
backend-rewrite preparation and Replay retain their feature-branch checks.
