# Redis write-to-read delivery

Global JSON and scalar identity formats preserve complete Source-to-Target
correspondence across writes and reads. An established Source ID delivers its
Target counterpart; an unknown historical input anchors itself. Structured JSON
needs no per-key field declaration. Accepted JSON writes can also supply bounded
same-key temporal counterparts when both Source and Target causality are proven.
This does not authorize additional reads.

For Source-proven variable GET observations of the latest raw SET identity,
add the key-local read-back permission:

```yaml
redis:
  keys:
    'chat:streaming:text_block:*':
      kind: identity
      formats: [{prefix: text-, format: decimal}]
      read_back: true
```

The engine lowers this to its existing SET/DEL/GET state owner. There is no
business lock rule, authored binding, resource/database selector or capture-first
plan sequence. Source proof on the proposed key declaration must establish all
writers, complete causal SET/DEL states and a positive write-to-read witness.
The published runtime policy omits that proof. Use the ordinary coordinator
`rule plan --file … --evidence …` and returned `rule apply --plan …` transaction.

If Source SET writes `old` and Target SET writes `new`, a later Source GET of
`old` delivers `new` only after that matched Target SET succeeds. A future write,
a different physical endpoint/database, another authentication identity or an
ambiguous write cannot supply the value. GETs before the first owned successful
SET retain their ordinary finite inventory and fence that first mutation.
Profiles with no supported successful SET remain ordinary finite traffic.

Current-state observations can reuse a proven response within one SET/DEL
lifetime, but every Source-observed state must still be observed by Target.
Creation, deletion and all other mutations remain finite. TTL, lane, response
outcome and successful delivery checks remain with the Redis adapter. See
[state observations](redis-state-observations.md) for state boundaries and limits.

Additional list or compound write/read relationships not expressed by the
compact key declaration retain their typed native `identity`/`redis_sequence`
read-back contracts. Such a contract owns selected GET or LRANGE values from
an earlier successful SET, RPUSH or LSET; every selected JSON pointer must
already belong to that native capture or contract. It does not replace ordinary
global field formats or authorize extra reads by itself.

Response and write values remain bounded to 1 MiB; native LRANGE is limited to
1024 elements, RPUSH to 128 elements, declarations to 16 per rule and selected
JSON pointers to 32. Runtime correspondence is bounded to 4096 entries / 16 MiB.
Public audits contain fingerprints and original write/read identities rather
than values. Immutable recording files are never modified. Complete Source
self-validation grants a fresh genuine Replay obligation, not a Target pass.
