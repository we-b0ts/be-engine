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

Add an exact request declaration for `AWS4-HMAC-SHA256` authorization.

```yaml
http:
  requests:
    - host: s3.example.test:9100
      method: GET
      path: /wegent-archives
      query: 'location='
      authorization: {kind: aws_sigv4}
```

Use the recorded host and port, method, path, and exact query, including empty
values with an explicit `=`. Replay checks each side's Credential date against
its own `x-amz-date` and compares the Access Key ID, region, service, scope
terminator and signed header list. The signature can change between executions
and must have the SigV4 HMAC digest format. Verify the policy through the managed
Session rule plan/apply workflow. [Session rules](session-regression.md#plan-implement-and-verify)
