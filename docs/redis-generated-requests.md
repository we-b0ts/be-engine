# Generated Redis request values

Use Source-backed `traffic-policy/v1` rules and the ordinary
`backend-rewrite rule plan --file … --evidence …` / `rule apply <plan-id>`
transaction. Source validation and successful Apply retain the obligation to
run genuine Target Replay. These contracts never edit the recording.

## Queue messages and result channels

Native `redis_sequence` JSON fields support:

- `{kind: random, format: hex, length: 64}` and canonical unpadded `base64url`
  with an explicit encoded ASCII length from 1 through 1024.
- `{kind: random, format: uuid, length: 36}` for canonical lowercase UUID text.
  This accepts UUID versions such as per-message UUID4 and process-owned UUID3;
  it does not assert a particular version or invent an identity reference.
- `{kind: random, format: string, max_length: 255}` for a nonempty string without
  control characters, bounded in UTF-8 bytes. Source and Target lengths may differ.
  The maximum must be 1 through 1024. `length` and `max_length` cannot coexist.

Every selected field requires generation proof. These random shape contracts do
not create cross-message identity bindings. Fields referring to the same task
must instead use an explicit identity capture and references.

`SUBSCRIBE` and `UNSUBSCRIBE` support an explicit single-subject key capture or
reference, in addition to existing SET key identities. For example, capture a
UUID4 from `result:{value}` under a bounded `result:` key selector, then reference
that binding in LPUSH JSON task ID, root ID and correlation ID fields. LPUSH and
RPUSH JSON contracts select explicit argument indexes from 1 through 128. Keep
the queue name, body, task name, delivery mode and all unselected fields exact.

Successful subscription confirmations translate only their subject to the
admitted Target key; their command and recorded integer count remain unchanged.
Multiple subjects and unsubscribe-all remain unsupported. Capturing a subject
does not authorize translating arbitrary notification payloads. Session affinity,
command order, required pushes and single-use consumption remain enforced.

## RPC payloads and signed URLs

Socket.IO Redis-adapter RPC PUBLISH uses protocol identity comparison copies
before selected request contracts. Publisher identity and callback-counter
bindings still commit only after complete request admission. The original Source
and independent Target arguments remain the evidence; callback results are never
rewritten by a request rule. Channel, event, room, SID, namespace and unselected
application data stay strict.

An example effect for Source-proven signed download links is:

```yaml
effect:
  kind: redis_sequence
  commands:
    - operation: PUBLISH
      arguments:
        1:
          kind: json
          fields:
            /data/0/plugins/*/download_path:
              kind: url
              query:
                X-Amz-Date:
                  kind: time
                  format: amz_date
                  relation: preserve_offset
                  clock_group: signing
                X-Amz-Credential:
                  kind: utc_date_segment
                  separator: /
                  index: 1
                  relative_to: X-Amz-Date
                X-Amz-Signature:
                  kind: random
                  format: hex
                  length: 64
            /data/0/plugins/*/download_url_expires_at:
              kind: time
              format: rfc3339
              relation: preserve_offset
              clock_group: expiry
```

Wrap this effect in a rule with the exact inbound API, Redis endpoint, database,
an exact channel selector and Source proof. The URL contract supports absolute
HTTP(S) URLs with up to 16 selected unique query names and 64 total query members,
within 16 KiB. It retains the original scheme, authority, path, query order,
unselected raw members and fragment. Duplicate query names fail validation.
Missing selected fields, wrong shapes and stale times fail; the signing time
uses the explicitly selected independent dependency request clocks.

`utc_date_segment` validates a decoded segment against its own selected query
timestamp's UTC `YYYYMMDD`, then compares every other segment exactly. In a
SigV4 credential it preserves the access key, region, service and terminator.
The signature rule validates its declared shape; it does not cryptographically
verify a signature without the signing credentials. This limitation and the
Source generation proof must be explicit in the proposed rule.

Whole `*` pointer segments expand arrays only. Array cardinality and every
unselected element field stay exact. An explicitly named clock group on an array
pattern is scoped to each matched array index, so independent plugin clock reads
do not become one shared clock. Matching names can still relate different fields
of the same element. Unnamed clocks retain the existing shared relationship.
