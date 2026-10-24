# Source-proven HTTP client metadata

Outbound SDK metadata can differ across languages while the consumer's behavior
stays the same. Unknown request headers remain strict by default. Use an explicit
`http_client_metadata` native effect only after tracing both the SDK producer and
the selected consumer, including middleware, to prove that these names do not
participate in authentication, routing, idempotency or application behavior.

```yaml
format: traffic-policy/v2
rules:
  - id: responses-sdk-metadata
    match:
      resource: {protocol: http, endpoint: 'chat-shell.example:8100'}
      operation: POST
      path: /v1/responses
    effect:
      kind: http_client_metadata
      headers: [x-stainless-lang, x-stainless-runtime, x-stainless-runtime-version]
    proof:
      source: sdk/base_client.py:platform_headers; chat_shell/response.py:create_response; chat_shell/main.py:middleware
      fact: The SDK emits runtime descriptions; the selected consumer and middleware do not use them for behavior.
```

The closed supported names are `x-stainless-arch`, `x-stainless-async`,
`x-stainless-lang`, `x-stainless-os`, `x-stainless-package-version`,
`x-stainless-read-timeout`, `x-stainless-retry-count`, `x-stainless-runtime` and
`x-stainless-runtime-version`. Select exact lowercase names individually; an
unknown name, wildcard, duplicate, empty selection or missing resource/method/
path is rejected. This is not a general header-ignore mechanism. A consumer that
reads these names needs a different Source conclusion.

The unified `rule plan` / `rule apply` transaction validates complete Source
requests and requires positive, available evidence for every selected name.
Rule ownership conflicts with another permission on the same header are rejected.
Source self-validation does not establish Target equivalence; apply requires a
fresh genuine Replay.

After matching an ordinary Case exchange, the audit reports selected missing,
added and changed metadata as observations. It retains values under existing
protection rules, the original difference kind, `comparison: observe` and the
authorizing `rule_id`. Usage counts identify the rule and audited headers.
Unselected headers retain their original modes. Endpoint/method/path/body/query,
finite exchanges, response delivery and Case ownership retain their own checks;
the permission does not select an exchange or relax Global/cross-case traffic.
Protected body-contract preflight uses the same scoped metadata permission without
changing either side's authenticated original witness.

For diagnosis, distinguish three facts: a matched HTTP request can still fail its
header audit; `protected: false` describes confidentiality and does not imply
acceptance; only an observation is nonblocking. Do not make a Rust Target pretend
to be the Python SDK to compensate for source-proven observational metadata.
Business headers and missing request events still need their own diagnosis.
