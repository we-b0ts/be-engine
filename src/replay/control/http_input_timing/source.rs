//! Prepare clock metadata once; expected responses and carrier values are not inputs.
use super::*;
use crate::http::stream::ResponseStream;
use crate::interaction::model::{InputActionKind, InputTranscript, Protocol};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(in crate::replay) struct SourceStream {
    pub index: usize,
    pub started_at: DateTime<Utc>,
    pub stream: ResponseStream,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct StreamSchedule {
    pub headers_ms: u64,
    pub chunks_ms: Vec<u64>,
    pub end_ms: u64,
    pub prefix_chunks: usize,
    pub prefix_required: bool,
    pub headers_after_close: bool,
    pub end_after_close: bool,
}

#[derive(Debug)]
pub(super) struct Plan {
    pub source_close_ms: u64,
    pub close_ms: u64,
    pub streams: BTreeMap<usize, StreamSchedule>,
}

#[derive(Deserialize)]
struct Request {
    timestamp: DateTime<Utc>,
    interaction: InputTranscript,
}

#[derive(Deserialize)]
struct Admission {
    case_id: String,
    timestamp: DateTime<Utc>,
}

pub(super) fn prepare(
    case: &ReplayCase,
    streams: Vec<SourceStream>,
    cap: u64,
) -> Result<Option<Plan>> {
    let raw = crate::request_headers::load_request_file(&case.dir.join("request.json"))?;
    let request: Request = serde_json::from_slice(&raw)?;
    request.interaction.validate()?;
    if !matches!(
        request.interaction.protocol,
        Protocol::Sse | Protocol::Ndjson
    ) || streams.is_empty()
    {
        return Ok(None);
    }
    let [action] = request.interaction.actions.as_slice() else {
        return Ok(None);
    };
    if action.sequence != 1
        || !action.after.is_empty()
        || action.gap_start_ms.is_some()
        || action.ack_ref.is_some()
        || action.compressible_gap
        || !matches!(&action.action, InputActionKind::Close {code:None,reason} if reason.is_empty())
    {
        return Ok(None);
    }
    // Older response-adopted HTTP captures wrote request.timestamp at headers.
    // Admission is the independently recorded origin of their input offsets.
    let admission = case.dir.join("admission.json");
    let epoch = if admission.is_file() {
        let admission: Admission = serde_json::from_slice(&std::fs::read(admission)?)?;
        ensure!(
            admission.case_id == case.id,
            "HTTP timing admission belongs to another Case"
        );
        admission.timestamp.min(request.timestamp)
    } else {
        request.timestamp
    };
    build(epoch, action.offset_ms, streams, cap).map(Some)
}

fn build(epoch: DateTime<Utc>, close: u64, streams: Vec<SourceStream>, cap: u64) -> Result<Plan> {
    let mut points = BTreeSet::from([0, close]);
    let mut prepared = Vec::with_capacity(streams.len());
    for source in streams {
        let start = u64::try_from((source.started_at - epoch).num_milliseconds())
            .context("HTTP stream began before its primary input origin")?;
        let offset = |at: u64| start.checked_add(at).context("HTTP Source clock overflow");
        let headers = offset(source.stream.headers_ms)?;
        let chunks = source
            .stream
            .chunks
            .iter()
            .map(|chunk| offset(chunk.at_ms))
            .collect::<Result<Vec<_>>>()?;
        let end = offset(source.stream.end_ms)?;
        ensure!(
            headers <= end
                && chunks.windows(2).all(|v| v[0] <= v[1])
                && chunks.first().is_none_or(|v| headers <= *v)
                && chunks.last().is_none_or(|v| *v <= end),
            "HTTP Source stream clocks are invalid"
        );
        points.extend([start, headers, end]);
        points.extend(chunks.iter().copied());
        prepared.push((source.index, headers, chunks, end));
    }
    let mut mapped = BTreeMap::new();
    let (mut previous, mut replay) = (0, 0u64);
    for point in points {
        replay = replay
            .checked_add((point - previous).min(cap))
            .context("HTTP replay clock overflow")?;
        mapped.insert(point, replay);
        previous = point;
    }
    let mut result = BTreeMap::new();
    for (index, headers, chunks, end) in prepared {
        let prefix_chunks = chunks.iter().take_while(|at| **at <= close).count();
        ensure!(
            result
                .insert(
                    index,
                    StreamSchedule {
                        headers_ms: mapped[&headers],
                        chunks_ms: chunks.iter().map(|at| mapped[at]).collect(),
                        end_ms: mapped[&end],
                        prefix_chunks,
                        prefix_required: headers <= close,
                        headers_after_close: headers > close,
                        end_after_close: end > close,
                    }
                )
                .is_none(),
            "duplicate HTTP stream timing reference"
        );
    }
    Ok(Plan {
        source_close_ms: close,
        close_ms: mapped[&close],
        streams: result,
    })
}
