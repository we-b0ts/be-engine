# Content formats and carrier bindings

The policy separates content formats, physical carrier positions and recording
behavior. Case capture uses the root `recording.case_paths` declaration:

```yaml
recording:
  case_paths:
    - /tasks/*
    - /attachments/*
```

The original path order, Source revision and native capture identity remain
unchanged. `recording` is serialized last. An optional `name` preserves a custom
capture identity; the default is `source-capture-http`. Ordinary declarations
need no `rules` list; empty `rules` are omitted. Extra native permissions that
cannot be represented losslessly retain their explicit rules.

## JSON string templates

Templates are global field formats. The Source layout selects one template;
the Target must retain its literals and validate every identity slot. Multiple
matching Source layouts reject as ambiguous. Once a layout matches, an invalid
Source or Target token cannot fall back to exact comparison. A Source string
matching no layout remains exact.

```yaml
json:
  fields:
    /session_id: {kind: identity, formats: [{prefix: vnc-, base64url: 24}, uuid]}
    /url:
      kind: template
      formats:
        - template: 'wss://stream.example.test/sessions/{session_id}?ticket={ticket}'
          fields:
            session_id: {prefix: vnc-, base64url: 24}
            ticket: {base64url: 43}
```

Slot values join the same case-local, complete typed identity correspondence
as ordinary JSON members. Extract the complete prefixed session ID to associate
it with `/session_id`; stripping the prefix would create a different value.
Base64url tokens use canonical encoding. Fixed URL host, path, query names and
delimiters stay strict. Delivery translates only declared slots, stages new
anchors until successful delivery and preserves immutable Source bytes.

## HTTP acquisition and generated paths

`http.requests` selects outbound request positions using an explicit authority,
method and path. `http.response_rewrite` selects recording-time response address
rewrites, separately from a global JSON URL format:

```yaml
http:
  response_rewrite:
    - name: sandbox-addresses
      host: control.example.test
      method: GET
      path: /sandboxes/*
      json_urls: [/base_url]
  requests:
    - host: objects.example.test:9100
      method: PUT
      path: /bucket/attachments/*
      path_identity:
        segment: 2
        template: '{nonce}_{created_at}_{owner}_{attachment}'
        fields:
          nonce: {hex: 12}
          created_at: {timestamp: '%Y%m%d%H%M%S'}
          owner: exact
          attachment: exact
        references: [object_storage, application_mysql]
```

Named reference resources must be declared under `resources`. Path identities
retain their explicit physical port, exact business fragments, Source-selected
timestamp behavior and cross-resource use permissions. An optional `api` keeps
an existing inbound API scope. Knowing an identity never authorizes arbitrary
SQL or string replacement outside those resource permissions.

URL acquisition retains the original authority semantics, including an absent
port. It discovers upstream addresses and registers recording routing. Empty
status/content-type filters retain the existing capture defaults. Capture
precedence remains ordered, and changing acquisition still requires fresh
recording; it is not a value-comparison exemption.
An optional rewrite `name` retains an existing capture identity during a
syntax-only migration, preserving its capture fingerprint and recorded routing
identity. New unnamed declarations derive a stable proof-independent identity.
`documents` declarations handle nested service-discovery and cache configuration
responses through explicit selectors, decoding steps and address formats.
See [dependency protocols and response rules](dependency-provider.md). The
kubeconfig adapter retains its framework-owned process and credential lifecycle.

## Codec bindings and generated headers

An API position can bind an encryption envelope and its private startup key.
Decrypted content without legacy local overrides uses the same global JSON
plan, including strict remainder, independent clocks and staged identities.
The encryption IV retains its original bijection checks.

```yaml
json:
  fields:
    /expire_at: {kind: time, formats: [unix_seconds]}
docx:
  fields:
    - {kind: timestamp, part: docProps/core.xml, element: 'dcterms:created', format: rfc3339}
api:
  GET /runtime:
    response:
      json:
        /user:
          encoding:
            envelope: base64_iv_aes_cbc_pkcs7
            key: {kind: startup, source: {kind: target_env, name: USER_AES_KEY}}
  GET /exports/docx:
    response:
      headers:
        content-disposition: {kind: date, parameter: filename, format: '%Y-%m-%d'}
      body: {codec: docx}
```

DOCX fields are declared once and reused by API codec bindings. A binding keeps
the original applicability scope; recognition of a DOCX package alone does not
authorize changing its timestamps. OPC package members and unselected XML bytes
remain strict. Selected timestamps retain their independently observed request
clock relationship. An unused DOCX declaration rejects.

Filename dates keep their original API scope because other filenames can
contain fixed business dates. Both `filename` and `filename*` retain parameter
presence, decoded dates and their correspondence. Prefix, suffix, extension,
other parameters, header counts and response status remain checked. Signature
positions coexist with these codec/header bindings under the same `api` map.

## Multipart protocol comparison

Complete supported Source `multipart/form-data` fixes the comparison codec.
Different outer boundaries and their corresponding Content-Type boundary
parameters may encode the same request. Ordered parts, part headers, filenames,
payload bytes, other Content-Type parameters and other request headers remain
strict. Target parsing failure cannot fall back after Source selection.
Unsupported Source encoding retains exact comparison.

This protocol behavior needs no project rule. Raw recordings, authenticated
witnesses and finite consumption retain their ordinary identities. Cross-case
sharing fingerprints remain based on the original bytes; multipart equivalence
does not extend sharing permissions. Runtime matching, final header audits and
plan/preflight use the same parser and comparison.

## Planning and rendering

Carrier and codec declarations lower to the existing typed capture, identity,
header and body owners. They do not introduce a second runtime evaluator.
Every proposed permission retains its own Source proof and inherited subtree
proofs; runtime rendering removes those explanations. Generated IDs exclude
proof text. Rendering folds only lossless canonical shapes and checks the
compiled fingerprints after a parse round trip. Extra native scope stays
explicit when the compact representation cannot preserve it.

Global format proposals are additive by default. A worker supplies its new
positions or formats, and the engine retains the current map. Formats append
without reordering earlier Source choices; duplicates are no-ops. Incompatible
kinds, signature profiles or physical patterns reject. Whole-section replacement
requires explicit `replace_sections` intent. Plans expose structured declaration
changes, complete coverage and verification obligations; a stale plan cannot
overwrite a concurrent addition. Source selects the comparison branch and the
Target must satisfy that same branch after any format addition.
