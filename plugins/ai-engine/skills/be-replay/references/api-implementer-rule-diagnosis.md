# Rule Diagnosis

Propose rules for time, ID and token values. Trace Source and Target behavior to
establish the exact value location, the Source file and symbol, and the
relationship the comparison must preserve. Use the
[shared rule evidence contract](rule-policy.md).

## Source Event Session

Start at the failed sequence. For dependency evidence, inspect the recorded
request and result by admission sequence and use the report-bound Target
observation when available. Inspect related sequences to establish where the
value came from and where it is reused. See [session workflow](session-regression.md).

| Rule | Diagnosis and supported placement |
| --- | --- |
| Time | Use `kind: time` for a Source-proven generated time in a recognized JSON field under `json.fields` or a supported primary response header under `http.headers`. Prove the encoding, units, clock and relative offset. For a copied input, trace the original read and subsequent write. |
| ID | Use `kind: identity` and a proven format for a generated ID in a recognized JSON field or a supported primary response header. The engine preserves equality for repeated complete Source IDs and distinctness for different IDs. Dependency identity mappings span the session. |
| Token | Use `kind: jwt` and the applicable named `signatures` profile for a JWT in recognized JSON. Use an exact API position for supported inbound re-signing or response token checks. Prove the signed claims, lifetime and key provenance. Return a startup key reference without including key material. See [signature profiles](../../../../../docs/signature-profiles.md). |

Redis script timestamps use a time rule for one exact key and one `EVAL` under
`redis.keys.<exact-key>.commands`. Specify the script's exact lowercase SHA-256
digest and `kind: time, formats: [unix_seconds]` for each selected scalar
argument. The first ARGV position is 3 for a single-key invocation because the
argument index starts at the script text. The engine compares selected slots
relative to each side's dependency request clock. The script, key, unselected
arguments and every recorded call remain strict.

Check that the live runtime binds the proposed format at the observed carrier.
JSON paths are root-relative to the recognized document. Session Replay compares
primary SSE and NDJSON body parts as bytes.

Return a `kind: rule` finding with the causal Source sequences and the policy
path. Include the proposed declaration, Source proof and residual differences in
the accompanying analysis. Verify the integrated change with a fresh full session.
