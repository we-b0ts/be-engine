# Global HTTP header formats

Declare a header once for all APIs and dependency endpoints:

```yaml
http:
  headers:
    x-amz-date: {kind: time, formats: [amz_date]}
    x-request-id: {kind: identity, formats: [uuid]}
```

Header names are case-insensitive. Presence, occurrence count and order stay
strict. Identical Source and Target values pass directly; changed times must
satisfy the shared relative-time kernel against independent recorded Source
and observed Target request clocks.
Framing and integrity headers, including Content-Length, Content-Encoding,
Digest and Signature, cannot declare value formats; their protocol or native
transformation owner must validate them.

Identity headers participate in the same case-local complete-value graph as
JSON and storage fields. Repeated Source values require repeated Target values,
and distinct Source identities cannot collapse. Header and body proposals are
validated together; a failed candidate publishes neither mapping.

Only declared headers receive format behavior. Transport, authentication,
client-metadata, URI, body, framing and finite-inventory contracts retain their
existing owners. Encrypted Source headers are decoded from the protected
snapshot before comparison; public diagnostics retain value protection.

Use the ordinary global rule plan/apply transaction. Per-API request-header
timestamp effects, separate timestamp validators and their special planners
are retired. Native signed-input transformations retain their own execution
owner.
