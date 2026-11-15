//! Read original namespace CONNECT metadata; retain no expected business payloads.
use super::Source;
use crate::interaction::model::InputTranscript;
use crate::replay::ReplayCase;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
pub(super) use traffic_protocol_http::interaction::sessions::source::{sessions, window};

pub(super) fn load(cases: &BTreeMap<String, ReplayCase>) -> Result<BTreeMap<String, Source>> {
    let mut result = BTreeMap::new();
    for (case, replay) in cases {
        let request_path = replay.dir.join("request.json");
        if !request_path.is_file() {
            continue;
        }
        let request: Value = serde_json::from_slice(
            &crate::request_headers::load_request_file(&request_path)
                .context("native namespace session INPUT could not be authenticated")?,
        )
        .context("invalid native namespace session INPUT")?;
        if request
            .pointer("/interaction/protocol")
            .and_then(Value::as_str)
            != Some("socket_io")
        {
            continue;
        }
        let Some(input) = serde_json::from_value::<InputTranscript>(request["interaction"].clone())
            .ok()
            .filter(|input| input.validate().is_ok())
        else {
            continue;
        };
        let path = ["expected-response.json", "expected_response.json"]
            .into_iter()
            .map(|name| replay.dir.join(name))
            .find(|path| path.is_file());
        let Some(path) = path else { continue };
        let mut output: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        crate::interaction::private::decrypt_output(&mut output, &path)
            .context("native namespace session Source output could not be authenticated")?;
        let namespaces = sessions(&input, &output);
        if !namespaces.is_empty() {
            result.insert(
                case.clone(),
                Source {
                    sids: namespaces,
                    window: window(&request, &input, &output),
                },
            );
        }
    }
    Ok(result)
}
