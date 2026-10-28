//! Source publishers select immutable self-echo lookup work before Replay readiness.
use super::*;
use crate::dependency_index::Paged;

impl Echoes {
    fn needs_index(&self, lane: &inventory::IndexedLane) -> bool {
        lane.kind != RedisSubscriptionKind::ShardChannel
            && self.channels.iter().any(|(target, channel)| {
                *target == endpoint(&lane.record)
                    && (lane.kind == RedisSubscriptionKind::Pattern || *channel == lane.subject)
            })
    }
}

impl PubSubState {
    pub(in crate::replay) fn prepare_echo_indices(&self) -> Result<()> {
        self.echoes.prepare_windows();
        let lanes = self
            .indexed
            .lanes
            .iter()
            .filter(|lane| self.echoes.needs_index(lane))
            .collect::<Vec<_>>();
        if lanes.is_empty() {
            return Ok(());
        }
        let started = std::time::Instant::now();
        let mut prepared = 0;
        tracing::info!(lanes = lanes.len(), "preparing Redis adapter echo indices");
        for lane in &lanes {
            let pages = lane
                .pages
                .as_ref()
                .context("adapter echo notification inventory is not sealed")?;
            prepared += usize::from(lane.echoes.get().is_none());
            lane.echoes
                .get_or_init(|| build(pages).map_err(|error| format!("{error:#}")))
                .as_ref()
                .map_err(|error| anyhow!("adapter echo index preparation failed: {error}"))?;
        }
        tracing::info!(
            lanes = lanes.len(),
            prepared_lanes = prepared,
            elapsed_ms = started.elapsed().as_millis(),
            "Redis adapter echo indices ready"
        );
        Ok(())
    }
}

fn build(
    pages: &Paged<NotificationEntry>,
) -> Result<BTreeMap<Digest, Vec<(usize, NotificationEntry)>>> {
    let mut result = BTreeMap::<Digest, Vec<(usize, NotificationEntry)>>::new();
    for page in 0..pages.pages() {
        for (offset, entry) in pages.read_page(page)?.into_iter().enumerate() {
            if let Some(digest) = entry.adapter_echo {
                result
                    .entry(digest)
                    .or_default()
                    .push((pages.page_start(page) + offset, entry));
            }
        }
    }
    Ok(result)
}
