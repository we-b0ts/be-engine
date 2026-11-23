# Redis write-to-read delivery

Redis Replay delivers the actual Target bytes from a successful write when the
recording establishes that a later read observed that write. This is built into
finite Case replay. Value rules still validate differences in the write request,
and each write and read still consumes its recorded exchange.

| Successful write | Reads that can deliver its stored values |
| --- | --- |
| Plain SET and MSET | GET and MGET |
| HSET and HMSET | HGET, HMGET and HGETALL |

HSET can write one or several fields. A response of zero can indicate a
successful overwrite. Each field keeps its own latest write. In MGET and
HMGET, delivery resolves each original response element separately. HGETALL
keeps the recorded field names and order.

The engine associates a Source bulk value with its preceding successful write
in the same Case, endpoint, database and key or hash field. Across
connections, the recording must establish the causal order. The Target write
must also deliver successfully before its value is used. Replacement and
deletion end the previous value's lifetime and release its retained bytes.
A later write can establish a new known value after earlier concurrent accesses
if it is proven to follow them. Commands with TTL or conditional
options, other unsupported mutations, and ambiguous order limit what can be
proven. Values with an unknown origin use ordinary finite replay.

A recorded nil stays nil, including individual MGET and HMGET elements. A
recorded empty HGETALL stays empty. A zero-byte bulk string is a present value.
Replay sends the complete bytes that Target supplied for a proven value,
including serialization choices such as JSON whitespace. An explicit response
binding still validates those bytes. Stored values use the write's implicit
value policy, including its clock, when the write is matched.

When the installed policy can affect Redis values, Replay collects causal
metadata during ordinary registration and keeps Target payloads only for
writes whose matched value bytes differ. The existing
recording supplies the command arguments, reply and order evidence. Ordinary
write-to-read delivery keeps finite request counts.
