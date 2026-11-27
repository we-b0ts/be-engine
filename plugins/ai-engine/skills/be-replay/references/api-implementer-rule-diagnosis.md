# Rule Diagnosis

Propose rules for time, ID and token values. Trace Source and Target behavior to
establish the exact value location, the Source file and symbol, and the
relationship the comparison must preserve. Use the
[shared rule evidence contract](rule-policy.md).

For a difference caused by a collection's iteration order, follow the Target
implementation guidance in [Set and map iteration](api-implementer-diagnosis.md#set-and-map-iteration).

## Source Event Session

Start at the assigned sequence. For dependency evidence, inspect the recorded
request and result by admission sequence and use the report-bound Target
observation when available. Inspect related sequences to establish where the
value came from and where it is reused. See [session workflow](session-regression.md).

| Rule | Diagnosis and supported placement |
| --- | --- |
| Time | Use `kind: time` for a Source-proven generated time in a recognized JSON field under `json.fields` or a supported primary response header under `http.headers`. Prove the encoding, units, clock and relative offset. For a copied input, trace the original read and subsequent write. |
| ID | Use `kind: identity` and a proven format for a generated ID in a recognized JSON field, a supported primary response header, or a Redis physical key slot. The engine preserves equality for repeated complete Source IDs and distinctness for different IDs across these surfaces in one Session. |
| Token | Use `kind: jwt` and the applicable named `signatures` profile for a JWT in recognized JSON. Use an exact API position for supported inbound re-signing or response token checks. Prove the signed claims, lifetime and key provenance. Return a startup key reference without including key material. See [signature profiles](../../../../../docs/signature-profiles.md). |

Declare a generated Redis physical key slot with one bounded wildcard under
`redis.keys`. For `vnc_session:vnc-xxx`, the wildcard extracts the complete
`vnc-xxx` ID. Redis JSON values and primary JSON responses can declare the same
ID at `json.fields./session_id` and share the mapping by complete typed value.
The mapping lasts for one Replay Session and commits after a complete match.
If the Redis key and JSON start with the same Source ID, they must agree on the
Target ID. Distinct Source IDs must map to distinct Target IDs.

```yaml
redis:
  keys:
    'vnc_session:*':
      key_format: {kind: identity, formats: [{prefix: vnc-, base64url: 24}]}
```

Top-level `kind` and `formats` on a Redis key entry govern its scalar stored
value. Use `key_format` for the physical key itself.

Redis script timestamps use a time rule for one exact key and one `EVAL` under
`redis.keys.<exact-key>.commands`. Specify the script's exact lowercase SHA-256
digest and `kind: time, formats: [unix_seconds]` for each selected scalar
argument. The first ARGV position is 3 for a single-key invocation because the
argument index starts at the script text. The engine compares selected slots
relative to each side's dependency request clock. The script, key, unselected
arguments and every recorded call remain strict.

For an outbound S3 request whose recorded `Authorization` uses
`AWS4-HMAC-SHA256`, scope `aws_sigv4` to its exact host, method, path and query.
This proposal matches the bucket-location request in `seq 4055`.

```yaml
format: traffic-policy/v3
http:
  requests:
    - host: s3.hj4.1.intra.weibo.com:9100
      method: GET
      path: /wegent-archives
      query: 'location='
      authorization: {kind: aws_sigv4}
```

Keep the trailing `=` from the recording. Managed Replay checks each signature's
format and the agreement between its Credential date and `x-amz-date`. It
compares the remaining Credential scope and `SignedHeaders` between executions.
Outbound `x-amz-date` is a built-in request-relative time comparison and also
applies to requests that carry the date header by itself.

Check that the live runtime binds the proposed format at the observed carrier.
JSON paths are root-relative to the recognized document. Session Replay compares
primary SSE and NDJSON body parts as bytes.

## Submit a rule plan

Write the smallest additive `traffic-policy/v3` fragment that describes the
proven relationship. Supply local `proof` where the declaration requires it.
The plan preserves the Source revision, time defaults, capture scope, and
other declarations. An API-specific policy selector still uses the actual
method when its schema requires it. [Traffic Policy](../../../../../docs/replay-policy.md)

For a proven Unix-seconds field, `rule.yaml` can contain the following.

```yaml
format: traffic-policy/v3
json:
  fields:
    /report/created_at: {kind: time, formats: [unix_seconds]}
```

Supply `plan.json`, its proposal, and the exact sequences file to the
coordinator for `be-replay rule plan --file /absolute/plan.json`. File paths
can be absolute or relative to `plan.json`. The engine registers the plan
against the active assignment and current failed Replay attempt.

```json
{
  "group": "reports",
  "assignment_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  "sequences_file": "rule-sequences.txt",
  "proposal_file": "rule.yaml",
  "source_evidence": {
    "source": "src/reports/serializer.rs#map_report",
    "fact": "map_report writes created_at using the wall clock in Unix seconds."
  },
  "checks": ["assigned report timestamp regression passed"]
}
```

The code integrator applies selected plans together. The coordinator verifies
the integrated policy with a fresh full session. [Integration workflow](code-integrator.md)
