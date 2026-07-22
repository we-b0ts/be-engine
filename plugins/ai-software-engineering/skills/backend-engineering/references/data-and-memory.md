# Data, JSON, And Memory Efficiency

Large backend payloads make allocation and copying part of correctness. A
one-megabyte response can transiently consume several times its wire size when
parsed into a generic tree, converted into domain objects, copied, logged, and
serialized again.

## Required Analysis

For large or frequent data paths, identify:

- maximum accepted and emitted sizes;
- number of simultaneous payloads;
- parsing and serialization representations;
- full-buffer copies and encoding conversions;
- compression and decompression expansion;
- logging, tracing, retry, and cache copies;
- retention across awaits, queues, and caches.

Reject or stream inputs before allocating beyond configured limits. Treat
compressed input limits separately from decoded-size limits.

## JSON And Serialization

Use typed parsing when it improves validation and avoids repeated tree walks.
Use streaming or incremental parsing and serialization when the contract and
framework support it and payload size justifies the complexity. Avoid repeated
parse/serialize cycles, generic-value cloning, string round trips, and pretty
printing on production hot paths.

Preserve the wire contract: missing, `null`, empty string, scalar kinds, number
precision, binary encodings, and array order can be semantically distinct. Do
not optimize by silently dropping fields or changing number representation.

Serialize once near the transport boundary when practical. Reuse immutable
byte buffers or slices instead of copying between layers. Buffer writes to
reduce system calls, but bound buffer capacity and define flush behavior.

## Collections, Caches, And Logs

Preallocate only from trustworthy bounded sizes. Cap maps, deduplication sets,
caches, aggregation windows, and per-request accumulators. Define eviction and
ownership for every cache.

Do not log complete large request or response bodies by default. Use bounded
previews, sizes, hashes, identifiers, and structured error context. Telemetry
must not retain payload objects longer than the request.

## Evidence

For material paths, compare representative payload latency, allocation count,
peak resident memory, and throughput before and after the change. A microbenchmark
that excludes parsing, allocation, I/O, or concurrency cannot support an
end-to-end capacity claim.
