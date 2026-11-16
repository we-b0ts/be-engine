//! Authenticated metadata access for native Socket.IO delivery windows.
use super::*;
use serde_json::Value;
use std::io::BufReader;
pub(super) use traffic_protocol_http::interaction::socketio::delivery_windows::Window;
use traffic_protocol_http::interaction::socketio::delivery_windows::{
    InputMetadata as Request, OutputMetadata as Response,
};

pub(super) fn load(root: &Path, selected: &BTreeMap<String, ReplayCase>) -> Result<Vec<Window>> {
    // A standard completed run provides *all* windows, including skipped Cases.
    // Without that boundary we cannot prove unique finite input ownership.
    let complete = root
        .ancestors()
        .any(|p| p.join("recording-run.json").is_file());
    let files = if complete {
        crate::dependency_index::store::recording_files(root)?.1
    } else {
        // Known namespaces still fence old timers, but incomplete run scope
        // cannot grant a unique Case projection.
        selected
            .values()
            .map(|case| case.dependencies_path.clone())
            .collect()
    };
    let mut windows = Vec::new();
    for file in files {
        let directory = file.parent().context("Case has no directory")?;
        let Some(request) = read_input(&directory.join("request.json"))? else {
            continue;
        };
        if !request.supports_delivery_windows() {
            continue;
        }
        let case = directory
            .file_name()
            .and_then(|name| name.to_str())
            .context("Case has no identity")?
            .to_owned();
        let (response_path, response) = if complete {
            let preferred = directory.join("expected-response.json");
            match read::<Response>(&preferred)? {
                Some(response) => (preferred, Some(response)),
                None => {
                    let legacy = directory.join("expected_response.json");
                    let response = read::<Response>(&legacy)?;
                    (legacy, response)
                }
            }
        } else {
            (directory.join("expected-response.json"), None)
        };
        if let Some(window) = Window::prepare(
            case.clone(),
            selected.contains_key(&case),
            complete,
            request,
            response,
            || read_outputs(&response_path),
        )? {
            windows.push(window);
            ensure!(
                windows.len() <= 16_384,
                "native notification window inventory exceeds bound"
            );
        }
    }
    Ok(windows)
}

fn read_input(path: &Path) -> Result<Option<Request>> {
    if !path
        .try_exists()
        .context("native notification INPUT unavailable")?
    {
        return Ok(None);
    }
    // Use the same authenticated in-memory view as request execution. Cipher
    // failures must propagate; they cannot downgrade INPUT to an unknown
    // namespace or release the obsolete subscription-age timer.
    let raw = crate::request_headers::load_request_file(path)
        .context("native notification INPUT unavailable")?;
    serde_json::from_slice(&raw)
        .map(Some)
        .context("invalid original native INPUT metadata")
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::File::open(path) {
        Ok(file) => serde_json::from_reader(BufReader::new(file))
            .map(Some)
            .context("invalid original native lifecycle metadata"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("original native lifecycle metadata unavailable"),
    }
}

fn read_outputs(path: &Path) -> Result<Option<Value>> {
    let Some(mut response) = read::<Value>(path)? else {
        return Ok(None);
    };
    crate::interaction::private::decrypt_output(&mut response, path)
        .context("native notification ACK checkpoint could not be authenticated")?;
    Ok(Some(response))
}
