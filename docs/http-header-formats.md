# Global HTTP header formats

Declare a header once for primary API response assertions:

```yaml
http:
  headers:
    x-amz-date: {kind: time, formats: [amz_date]}
    x-request-id: {kind: identity, formats: [uuid]}
```

Header names are case-insensitive. Presence, occurrence count and order stay
strict. There is no header-absence waiver, including for SDK metadata such
as `x-stainless-*`; those headers are not a generic ignored prefix. Identical
Source and Target values pass directly; changed times must
satisfy the shared relative-time kernel against independent recorded Source
and observed Target request clocks.
Framing and integrity headers, including Content-Length, Content-Encoding,
Digest and Signature, cannot declare value formats; their protocol or native
transformation owner must validate them.

Identity headers participate in the same case-local complete-value graph as
JSON and storage fields. Repeated Source values require repeated Target values,
and distinct Source identities cannot collapse. Header and body proposals are
validated together; a failed candidate publishes neither mapping.

Encrypted Source headers are decoded from the protected snapshot before
comparison. Public diagnostics retain value protection.

Use the ordinary global rule plan/apply transaction. Per-API request-header
timestamp effects, separate timestamp validators and their special planners
are retired. Native signed-input transformations retain their own execution
owner.

## Outbound SigV4 requests

Managed Event Session Replay automatically compares outbound `x-amz-date`
relative to each side's dependency request clock. This treatment also applies
when a request carries the date header by itself.

Replay first compares the recorded and live `Authorization` values exactly.
When the values differ, it can compare two recognized `AWS4-HMAC-SHA256`
headers automatically. This works without a policy file or a request rule.

To restrict SigV4 comparison to particular endpoints, declare their recorded
hosts and ports in `http.requests`.

```yaml
http:
  requests:
    - host: s3.example.test:9100
      authorization: {kind: aws_sigv4}
```

When SigV4 declarations are present, Replay uses their selectors. To limit a
declaration to one route, specify both `method` and `path`. Use the exact
`query` when present, including an explicit `=` for empty values. Replay
compares each request's method, path and query against the recording.

Replay checks each side's Credential date against its own `x-amz-date` and
compares the Access Key ID, region, service, scope terminator and signed header
list. The signature value can change between executions and must have the
SigV4 HMAC digest format.
