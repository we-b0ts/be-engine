//! Authenticated private interaction payloads; routing and timing stay inspectable.
use crate::request_headers::EvidenceCipher;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

const PREFIX: &str = "traffic-e2e:enc:";
const OUTPUT_ENVELOPE: &str = "private_interaction_output";
const PRIVATE_HEADERS: &str = "x-traffic-e2e-private-headers";

pub(crate) fn protect_request(request: &mut Value, path: &Path) -> Result<()> {
    if request.get("interaction").is_none_or(Value::is_null) {
        return Ok(());
    }
    if request.get("private_headers").is_some() {
        return Ok(());
    }
    let cipher = EvidenceCipher::from_path(path)?;
    let headers = request.get("headers").cloned().unwrap_or_else(|| json!({}));
    request["private_headers"] = Value::String(encrypt(
        &cipher,
        "interaction-input/v1/headers",
        &serde_json::to_vec(&headers)?,
    )?);
    request["headers"] = json!({});
    if let Some(data) = request.pointer_mut("/body/data") {
        protect_string(data, &cipher, "interaction-input/v1/body")?;
    }
    if request.get("private_uri").is_none() {
        let uri = request
            .get("uri")
            .and_then(Value::as_str)
            .context("interaction request has no URI")?;
        let parsed: hyper::Uri = uri.parse().context("invalid interaction request URI")?;
        if parsed.query().is_some() {
            let public = parsed.path().to_owned();
            let encrypted = encrypt(&cipher, "interaction-input/v1/uri", uri.as_bytes())?;
            request["private_uri"] = Value::String(encrypted);
            request["uri"] = Value::String(public);
        }
    }
    visit_actions(request, |action, label| {
        let kind = action
            .get("kind")
            .and_then(Value::as_str)
            .context("interaction input has no action kind")?;
        match kind {
            "message" => protect_string(
                action
                    .pointer_mut("/message/data")
                    .context("interaction message has no data")?,
                &cipher,
                &format!("{label}/message"),
            ),
            "close" => protect_string(
                action
                    .get_mut("reason")
                    .context("interaction close has no reason")?,
                &cipher,
                &format!("{label}/reason"),
            ),
            "upgrade" => {
                protect_string(
                    action
                        .get_mut("uri")
                        .context("interaction upgrade has no URI")?,
                    &cipher,
                    &format!("{label}/uri"),
                )?;
                let headers = action
                    .get_mut("headers")
                    .context("interaction upgrade has no headers")?;
                {
                    let encrypted = encrypt(
                        &cipher,
                        &format!("{label}/headers"),
                        &serde_json::to_vec(headers)?,
                    )?;
                    *headers = json!({ PRIVATE_HEADERS: [encrypted] });
                }
                Ok(())
            }
            _ => anyhow::bail!("unsupported private interaction input kind"),
        }
    })?;
    Ok(())
}

pub(crate) fn decrypt_request(request: &mut Value, path: &Path) -> Result<bool> {
    let Some(headers) = request.get("private_headers") else {
        ensure!(
            request.get("private_uri").is_none(),
            "private interaction URI has no authenticated input envelope"
        );
        return Ok(false);
    };
    let cipher = EvidenceCipher::from_path(path)?;
    let encrypted = headers
        .as_str()
        .context("private interaction headers must be a string")?;
    let plaintext = cipher.decrypt("interaction-input/v1/headers", encrypted)?;
    request["headers"] = serde_json::from_slice(&plaintext)
        .context("private interaction headers are invalid JSON")?;
    request
        .as_object_mut()
        .context("interaction request must be an object")?
        .remove("private_headers");
    let mut changed = true;
    if let Some(data) = request.pointer_mut("/body/data") {
        decrypt_string(data, &cipher, "interaction-input/v1/body")?;
    }
    if let Some(encrypted) = request.get("private_uri") {
        let encrypted = encrypted
            .as_str()
            .context("private interaction URI must be a string")?;
        let plaintext = cipher.decrypt("interaction-input/v1/uri", encrypted)?;
        request["uri"] = Value::String(
            String::from_utf8(plaintext).context("private interaction URI is not UTF-8")?,
        );
        request
            .as_object_mut()
            .context("interaction request must be an object")?
            .remove("private_uri");
        changed = true;
    }
    visit_actions(request, |action, label| {
        let kind = action
            .get("kind")
            .and_then(Value::as_str)
            .context("interaction input has no action kind")?;
        match kind {
            "message" => {
                changed |= decrypt_string(
                    action
                        .pointer_mut("/message/data")
                        .context("interaction message has no data")?,
                    &cipher,
                    &format!("{label}/message"),
                )?
            }
            "close" => {
                changed |= decrypt_string(
                    action
                        .get_mut("reason")
                        .context("interaction close has no reason")?,
                    &cipher,
                    &format!("{label}/reason"),
                )?
            }
            "upgrade" => {
                changed |= decrypt_string(
                    action
                        .get_mut("uri")
                        .context("interaction upgrade has no URI")?,
                    &cipher,
                    &format!("{label}/uri"),
                )?;
                let headers = action
                    .get_mut("headers")
                    .context("interaction upgrade has no headers")?;
                if let Some(encrypted) = headers.get(PRIVATE_HEADERS) {
                    let encrypted = encrypted
                        .as_array()
                        .filter(|values| values.len() == 1)
                        .and_then(|values| values[0].as_str())
                        .context("invalid private interaction upgrade headers")?;
                    let plaintext = cipher.decrypt(&format!("{label}/headers"), encrypted)?;
                    *headers = serde_json::from_slice(&plaintext)
                        .context("invalid private interaction header JSON")?;
                    changed = true;
                }
            }
            _ => anyhow::bail!("unsupported private interaction input kind"),
        }
        Ok(())
    })?;
    Ok(changed)
}

pub(crate) fn protect_output(response: &mut Value, path: &Path) -> Result<()> {
    if response.get("interaction").is_none_or(Value::is_null)
        || response.get(OUTPUT_ENVELOPE).is_some()
    {
        return Ok(());
    }
    let role = output_role(response);
    let cipher = EvidenceCipher::from_path(path)?;
    if let Some(headers) = response.get("headers") {
        response["private_interaction_output_headers"] = Value::String(encrypt(
            &cipher,
            &format!("interaction-output/v1/{role}/headers"),
            &serde_json::to_vec(headers)?,
        )?);
        response["headers"] = json!({});
    }
    visit_events(response, |data, label| protect_string(data, &cipher, label))?;
    if let Some(reason) = response.pointer_mut("/interaction/end/close/reason") {
        protect_string(
            reason,
            &cipher,
            &format!("interaction-output/v1/{role}/close/reason"),
        )?;
    }
    response[OUTPUT_ENVELOPE] = json!({"version":1,"role":role});
    // Semantic observations own assertions. Keep no duplicate plaintext stream body.
    if response
        .get("interaction")
        .is_some_and(|value| !value.is_null())
    {
        response["body"] = json!({"encoding":"utf8","data":"","truncated":false});
    }
    Ok(())
}

pub(crate) fn decrypt_output(response: &mut Value, path: &Path) -> Result<bool> {
    let Some(envelope) = response.get(OUTPUT_ENVELOPE) else {
        return Ok(false);
    };
    ensure!(
        envelope.get("version").and_then(Value::as_u64) == Some(1),
        "unsupported private interaction output version"
    );
    ensure!(
        envelope.get("role").and_then(Value::as_str) == Some(output_role(response)),
        "private interaction output channel mismatch"
    );
    let cipher = EvidenceCipher::from_path(path)?;
    let role = output_role(response);
    if let Some(headers) = response.get("private_interaction_output_headers") {
        let encrypted = headers
            .as_str()
            .context("private interaction output headers must be a string")?;
        let plaintext =
            cipher.decrypt(&format!("interaction-output/v1/{role}/headers"), encrypted)?;
        response["headers"] = serde_json::from_slice(&plaintext)
            .context("private interaction output headers are invalid JSON")?;
        response
            .as_object_mut()
            .context("interaction output must be an object")?
            .remove("private_interaction_output_headers");
    }
    visit_events(response, |data, label| {
        decrypt_string(data, &cipher, label).map(|_| ())
    })?;
    if let Some(reason) = response.pointer_mut("/interaction/end/close/reason") {
        decrypt_string(
            reason,
            &cipher,
            &format!("interaction-output/v1/{role}/close/reason"),
        )?;
    }
    response
        .as_object_mut()
        .context("interaction output must be an object")?
        .remove(OUTPUT_ENVELOPE);
    Ok(true)
}

fn output_role(response: &Value) -> &'static str {
    if response.get("version").is_some() {
        "target"
    } else {
        "source"
    }
}

fn visit_actions(
    request: &mut Value,
    mut visit: impl FnMut(&mut Value, &str) -> Result<()>,
) -> Result<()> {
    let Some(interaction) = request
        .get_mut("interaction")
        .filter(|value| !value.is_null())
    else {
        return Ok(());
    };
    let Some(actions) = interaction.get_mut("actions") else {
        return Ok(());
    };
    for (index, action) in actions
        .as_array_mut()
        .context("interaction actions must be an array")?
        .iter_mut()
        .enumerate()
    {
        let sequence = action
            .get("sequence")
            .and_then(Value::as_u64)
            .context("interaction input has no sequence")?;
        let label = format!("interaction-input/v1/action/{index}/{sequence}");
        visit(
            action
                .get_mut("action")
                .context("interaction input has no action")?,
            &label,
        )?;
    }
    Ok(())
}

fn visit_events(
    response: &mut Value,
    mut visit: impl FnMut(&mut Value, &str) -> Result<()>,
) -> Result<()> {
    // Actual responses require version; Source response records have no version field.
    // Including the role authenticates the two independent output channels separately.
    let role = output_role(response);
    let Some(interaction) = response
        .get_mut("interaction")
        .filter(|value| !value.is_null())
    else {
        return Ok(());
    };
    let events = interaction
        .get_mut("events")
        .and_then(Value::as_array_mut)
        .context("interaction output has no event array")?;
    for (index, event) in events.iter_mut().enumerate() {
        let sequence = event
            .get("sequence")
            .and_then(Value::as_u64)
            .context("interaction output has no sequence")?;
        let label = format!("interaction-output/v1/{role}/event/{index}/{sequence}");
        visit(
            event
                .pointer_mut("/message/data")
                .context("interaction output has no message data")?,
            &label,
        )?;
    }
    Ok(())
}

fn protect_string(value: &mut Value, cipher: &EvidenceCipher, label: &str) -> Result<()> {
    let text = value
        .as_str()
        .context("private interaction payload must be a string")?;
    *value = Value::String(encrypt(cipher, label, text.as_bytes())?);
    Ok(())
}

fn decrypt_string(value: &mut Value, cipher: &EvidenceCipher, label: &str) -> Result<bool> {
    let text = value
        .as_str()
        .context("private interaction payload must be a string")?;
    ensure!(
        text.starts_with(PREFIX),
        "private interaction payload has an unprotected value"
    );
    let bytes = cipher.decrypt(label, text)?;
    *value = Value::String(
        String::from_utf8(bytes).context("private interaction payload is not UTF-8")?,
    );
    Ok(true)
}

fn encrypt(cipher: &EvidenceCipher, label: &str, bytes: &[u8]) -> Result<String> {
    let encrypted = cipher.encrypt(label, bytes)?;
    ensure!(
        encrypted.starts_with(PREFIX),
        "private interaction encryption format is invalid"
    );
    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> (tempfile::TempDir, std::path::PathBuf) {
        let project = tempfile::tempdir().unwrap();
        let path = project
            .path()
            .join(".traffic-e2e/local/artifacts/recordings/case/request.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::platform::encryption_key::load_or_create(project.path()).unwrap();
        (project, path)
    }

    #[test]
    fn private_inputs_roundtrip_without_encrypted_headers_and_keep_public_timing() {
        let (_project, path) = project();
        let original = json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=polling&token=query-secret","headers":{},
        "interaction":{"protocol":"socket_io","actions":[
            {"sequence":1,"offset_ms":5,"action":{"kind":"message","message":{"kind":"text","data":"40{\"token\":\"connect-secret\"}"}}},
            {"sequence":2,"offset_ms":6,"action":{"kind":"upgrade","uri":"/socket.io/?sid=private-session","headers":{"authorization":["Bearer upgrade-secret"]}}},
            {"sequence":3,"offset_ms":7,"action":{"kind":"close","reason":"private close detail","code":1000}}
        ]}});
        let mut protected = original.clone();
        protect_request(&mut protected, &path).unwrap();
        let encoded = serde_json::to_string(&protected).unwrap();
        for secret in [
            "query-secret",
            "connect-secret",
            "upgrade-secret",
            "private-session",
            "private close detail",
        ] {
            assert!(!encoded.contains(secret));
        }
        assert_eq!(protected["uri"], "/socket.io/");
        assert_eq!(protected["interaction"]["actions"][0]["offset_ms"], 5);
        std::fs::write(&path, serde_json::to_vec(&protected).unwrap()).unwrap();
        let decoded: Value =
            serde_json::from_slice(&crate::request_headers::load_request_file(&path).unwrap())
                .unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn output_authentication_binds_channel_index_and_sequence() {
        let (_project, path) = project();
        let mut output = json!({"headers":{"sec-websocket-protocol":["header-secret"],"set-cookie":["cookie-secret"]},"body":{"data":"raw secret duplicate"},"interaction":{"events":[
            {"sequence":1,"message":{"data":"first-secret"}}, {"sequence":2,"message":{"data":"second-secret"}}
        ]}});
        protect_output(&mut output, &path).unwrap();
        assert!(!output.to_string().contains("secret"));
        let mut reordered = output.clone();
        reordered["interaction"]["events"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(decrypt_output(&mut reordered, &path).is_err());
        let mut wrong_channel = output.clone();
        wrong_channel["version"] = json!(1);
        assert!(decrypt_output(&mut wrong_channel, &path).is_err());
        assert!(decrypt_output(&mut output, &path).unwrap());
        assert_eq!(
            output["interaction"]["events"][0]["message"]["data"],
            "first-secret"
        );
        assert_eq!(
            output["headers"]["sec-websocket-protocol"][0],
            "header-secret"
        );
        assert_eq!(output["headers"]["set-cookie"][0], "cookie-secret");
    }

    #[test]
    fn protected_inputs_without_a_managed_key_fail_closed() {
        let (_project, path) = project();
        let mut request = json!({"uri":"/stream?token=secret", "interaction":{"actions":[]}});
        protect_request(&mut request, &path).unwrap();
        let unrelated = tempfile::tempdir().unwrap();
        if std::env::var(crate::request_headers::ENCRYPTION_KEY_ENV).is_err() {
            assert!(decrypt_request(&mut request, &unrelated.path().join("request.json")).is_err());
        }
    }
}
