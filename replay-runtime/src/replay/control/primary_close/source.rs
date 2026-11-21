//! Prepare clock metadata once; expected responses and carrier values are not inputs.
use super::*;
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub(crate) struct StreamSchedule {
    #[allow(dead_code)]
    pub headers_ms: u64,
    #[allow(dead_code)]
    pub chunks_ms: Vec<u64>,
    #[allow(dead_code)]
    pub end_ms: u64,
    #[allow(dead_code)]
    pub prefix_chunks: usize,
    pub prefix_required: bool,
    #[allow(dead_code)]
    pub headers_after_close: bool,
    #[allow(dead_code)]
    pub end_after_close: bool,
}

#[derive(Debug)]
pub(super) struct Plan {
    pub source_close_ms: u64,
    pub close_ms: u64,
    pub streams: BTreeMap<ProtocolExchange, StreamSchedule>,
}

pub(super) fn prepare(
    input: Option<crate::replay::protocol_runtime::primary_close::SourceInput>,
    streams: Vec<SourceStream>,
    cap: u64,
) -> Result<Option<Plan>> {
    let Some(input) = input.filter(|_| !streams.is_empty()) else {
        return Ok(None);
    };
    build(input.epoch, input.close_ms, streams, cap).map(Some)
}

fn build(epoch: DateTime<Utc>, close: u64, streams: Vec<SourceStream>, cap: u64) -> Result<Plan> {
    let mut points = BTreeSet::from([0, close]);
    let mut prepared = Vec::with_capacity(streams.len());
    for source in streams {
        let elapsed = (source.started_at - epoch)
            .to_std()
            .context("dependency stream began before its primary input origin")?;
        // Rounding down could move a fractional-millisecond post-close frame
        // before the integral input cutoff. Preserve that strict ordering.
        let start = u64::try_from(elapsed.as_nanos().div_ceil(1_000_000))
            .context("dependency stream request offset exceeds the timing range")?;
        let offset = |at: u64| start.checked_add(at).context("Source clock overflow");
        let headers = offset(source.headers_ms)?;
        let chunks = source
            .chunks_ms
            .iter()
            .map(|at| offset(*at))
            .collect::<Result<Vec<_>>>()?;
        let end = offset(source.end_ms)?;
        ensure!(
            headers <= end
                && chunks.windows(2).all(|v| v[0] <= v[1])
                && chunks.first().is_none_or(|v| headers <= *v)
                && chunks.last().is_none_or(|v| *v <= end),
            "Source stream clocks are invalid"
        );
        points.extend([start, headers, end]);
        points.extend(chunks.iter().copied());
        prepared.push((source.reference, headers, chunks, end));
    }
    let mut mapped = BTreeMap::new();
    let (mut previous, mut replay) = (0, 0u64);
    for point in points {
        replay = replay
            .checked_add((point - previous).min(cap))
            .context("Replay clock overflow")?;
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
            "duplicate dependency stream timing reference"
        );
    }
    Ok(Plan {
        source_close_ms: close,
        close_ms: mapped[&close],
        streams: result,
    })
}
