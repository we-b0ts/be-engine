//! A clean original interaction proves its finite Case dependency obligations.
use super::*;
use crate::interaction::model::{ClientTransportEnd, EndReason, Protocol};
use crate::interaction::policy::InteractionPolicy;
use serde_json::Value;
use std::fs::File;
use std::io::{BufReader, Read};

#[cfg(test)]
mod tests;

#[derive(Deserialize)]
struct Request {
    interaction: Option<Input>,
}

#[derive(Deserialize)]
struct Input {
    version: Option<u8>,
    protocol: Option<Protocol>,
    policy: Option<InteractionPolicy>,
    #[serde(default)]
    actions: Vec<InputOffset>,
}

#[derive(Deserialize)]
struct InputOffset {
    offset_ms: u64,
    #[serde(default)]
    action: Option<InputKind>,
}

/// Only the termination tag is needed; message payloads remain unread.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum InputKind {
    TransportEnd {
        end: ClientTransportEnd,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct Response {
    #[serde(default)]
    duration_ms: Option<u64>,
    interaction: Option<Completion>,
}

#[derive(Deserialize)]
struct Completion {
    version: Option<u8>,
    protocol: Option<Protocol>,
    end: Option<End>,
}

#[derive(Deserialize)]
struct End {
    reason: Option<EndReason>,
    clean: Option<bool>,
}

pub(super) async fn from_complete_source(
    case_dir: &Path,
    execution_allowance: Duration,
    evidence: &EvidenceRegistry,
) -> Result<Option<Metadata>> {
    let directory = case_dir.to_owned();
    let evidence = evidence.clone();
    tokio::task::spawn_blocking(move || load(&directory, execution_allowance, &evidence))
        .await
        .context("interaction dependency inventory preparation failed")?
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to open interaction metadata"),
    };
    ensure!(
        file.metadata()?.is_file(),
        "interaction metadata is not a file"
    );
    serde_json::from_reader(BufReader::new(file))
        .map(Some)
        .context("invalid interaction metadata")
}

fn load(
    case_dir: &Path,
    execution_allowance: Duration,
    evidence: &EvidenceRegistry,
) -> Result<Option<Metadata>> {
    let Some(request) = read_json::<Request>(&case_dir.join("request.json"))? else {
        return Ok(None);
    };
    let Some(input) = request.interaction else {
        return Ok(None);
    };
    let (Some(version), Some(protocol), Some(policy)) =
        (input.version, input.protocol, input.policy)
    else {
        // Older namespace/ingress hints can contain only the protocol name.
        // They are not a complete interaction program or a new tail proof.
        return Ok(None);
    };
    if !matches!(protocol, Protocol::SocketIo | Protocol::WebSocket) {
        return Ok(None);
    }
    ensure!(
        version == crate::interaction::model::TRANSCRIPT_VERSION,
        "unsupported interaction input version"
    );
    policy.validate()?;
    ensure!(
        input
            .actions
            .windows(2)
            .all(|pair| pair[0].offset_ms <= pair[1].offset_ms),
        "interaction Source input offsets decrease"
    );
    let last_input_ms = input.actions.last().map_or(0, |action| action.offset_ms);
    let response = match read_json::<Response>(&case_dir.join("expected-response.json"))? {
        Some(response) => Some(response),
        None => read_json::<Response>(&case_dir.join("expected_response.json"))?,
    };
    let Some(response) = response else {
        return Ok(None);
    };
    // Read only lifecycle and elapsed-time metadata. Source frame contents,
    // status and body cannot become Target inputs or completion signals.
    let Some(completion) = response.interaction else {
        return Ok(None);
    };
    let (Some(completion_version), Some(completion_protocol), Some(end)) =
        (completion.version, completion.protocol, completion.end)
    else {
        return Ok(None);
    };
    ensure!(
        completion_version == crate::interaction::model::TRANSCRIPT_VERSION
            && completion_protocol == protocol,
        "interaction Source completion has a different protocol or version"
    );
    let (Some(clean), Some(reason)) = (end.clean, end.reason) else {
        return Ok(None);
    };
    let transport_end = input
        .actions
        .last()
        .and_then(|action| match &action.action {
            Some(InputKind::TransportEnd { end }) => Some(*end),
            _ => None,
        });
    if !clean
        || (reason == EndReason::ClientTransportEnd) != transport_end.is_some()
        || !matches!(
            reason,
            EndReason::ServerEof
                | EndReason::ClientClose
                | EndReason::BusinessIdle
                | EndReason::ClientTransportEnd
        )
    {
        // Incomplete captures retain the existing transport/started-I/O
        // cleanup behavior; they cannot prove an unstarted business tail.
        return Ok(None);
    }
    let bytes = crate::dependency_index::scoped::read_bytes_for_replay(
        &case_dir.join("dependencies.jsonl"),
    )
    .context("interaction completion requires its original dependency inventory")?;
    let Some(references) = inventory(bytes.as_slice(), evidence)? else {
        return Ok(None);
    };
    let budget = execution_allowance
        .checked_add(Duration::from_millis(response.duration_ms.unwrap_or(0)))
        .context("interaction Source elapsed time exceeds the request budget range")?;
    // Compression can move wire close before a normal sleeping disconnect
    // hook finishes. Its recorded post-input interval supplements the idle
    // watchdog; it neither sleeps unconditionally nor supplies a Target reply.
    let post_input_ms = response
        .duration_ms
        .map(|elapsed| {
            elapsed
                .checked_sub(last_input_ms)
                .context("interaction Source duration precedes its last input")
        })
        .transpose()?
        .unwrap_or(0);
    Ok(Some(Metadata {
        recorded_idle_completion: false,
        normal_completion: true,
        request_timeout_ms: budget.as_millis().try_into()?,
        interaction_post_input_ms: Some(post_input_ms),
        references: references.into_iter().collect(),
        strict_references: BTreeSet::new(),

        source_stop_required: false,
        source_stop_after_ms: None,
        cleanup_refs: BTreeSet::new(),
        failure_completion: false,
        timeout_completion: false,
    }))
}

fn inventory(
    reader: impl Read,
    evidence: &EvidenceRegistry,
) -> Result<Option<BTreeSet<RecordedReference>>> {
    let mut references = BTreeSet::new();
    for event in serde_json::Deserializer::from_reader(reader).into_iter::<Value>() {
        let event = event.context("invalid interaction dependency")?;
        if !evidence.supports_interaction_inventory(&event) || event["lifecycle_cleanup"] == true {
            // This automatic legacy fallback cannot prove these obligations.
            // Preserve their existing cleanup path, rather than rejecting a
            // previously replayable interaction or claiming a partial inventory.
            return Ok(None);
        }
        if let Some(reference) = reference(&event, evidence)? {
            ensure!(
                references.insert(reference),
                "interaction inventory repeats an exchange"
            );
            if references.len() > MAX_SELECTED_REFS {
                return Ok(None);
            }
        }
    }
    Ok(Some(references))
}
