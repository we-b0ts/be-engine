//! Select external original slots, retaining original subscription and room bytes.
use super::*;

impl super::super::super::RedisReplayState {
    pub(in crate::replay) fn prepare_native_clock(
        &mut self,
        root: &Path,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<()> {
        self.pubsub.prepare_native_clock(root, cases)
    }
}

impl PubSubState {
    fn prepare_native_clock(
        &mut self,
        root: &Path,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<()> {
        if self.pushes.is_empty() && self.indexed.total == 0 {
            return Ok(());
        }
        let windows = source::load(root, cases)?;
        let namespaces = windows
            .iter()
            .filter(|window| window.selected)
            .flat_map(|window| window.namespaces.iter().cloned())
            .collect::<BTreeSet<_>>();
        if namespaces.is_empty() {
            return Ok(());
        }
        let source_count = self
            .pushes
            .len()
            .checked_add(self.indexed.total)
            .context("native notification Source inventory exceeds address space")?;
        let mut entries = Vec::new();
        for (index, push) in self.pushes.iter().enumerate() {
            if !push.source.is_run_level() || push.record.rpc_request.is_some() {
                continue;
            }
            let raw = push.bytes()?;
            let Some(frame) = parse_pubsub_push(&raw)? else {
                continue;
            };
            let namespace = rpc::notification_namespace(&frame.channel, &frame.payload);
            if let Some(entry) = select(
                &windows,
                &namespaces,
                &self.echoes,
                &push.record,
                PushId::Inline(index),
                push.record.timestamp,
                push.evidence
                    .as_ref()
                    .map_or(index, |reference| reference.location.line),
                rpc::echo_digest(&frame.channel, &frame.payload),
                namespace.as_deref(),
                push.evidence.clone(),
                push.raw.clone(),
            )? {
                reserve_entry(&mut entries, source_count)?;
                entries.push(entry);
            }
        }
        for (lane_index, lane) in self.indexed.lanes.iter().enumerate() {
            let pages = lane
                .pages
                .as_ref()
                .context("native notification inventory is not sealed")?;
            for page in 0..pages.pages() {
                for (offset, entry) in pages.read_page(page)?.into_iter().enumerate() {
                    if let Some(entry) = select(
                        &windows,
                        &namespaces,
                        &self.echoes,
                        &lane.record,
                        PushId::Indexed {
                            lane: lane_index,
                            index: pages.page_start(page) + offset,
                        },
                        entry.timestamp,
                        entry.location.line,
                        entry.adapter_echo,
                        entry.adapter_namespace.as_deref(),
                        Some(lane.source.reference(entry.location)),
                        Vec::new(),
                    )? {
                        reserve_entry(&mut entries, source_count)?;
                        entries.push(entry);
                    }
                }
            }
        }
        ensure!(
            entries.len() <= source_count,
            "native notification projection exceeds Source inventory"
        );
        // A clock inversion cannot reorder the physical Source lane to match a
        // request clock. Keep that Case's original slots unconsumed instead.
        entries.sort_by_key(|entry| entry.ordinal);
        let mut last = BTreeMap::new();
        let mut blocked = BTreeSet::new();
        for entry in &entries {
            let key = (entry.case.clone(), entry.anchor);
            if last
                .insert(key, entry.source_at)
                .is_some_and(|before| before > entry.source_at)
            {
                blocked.insert(entry.case.clone());
            }
        }
        entries.retain(|entry| !blocked.contains(&entry.case));
        entries.sort_by_key(|entry| (entry.offset, entry.ordinal));
        tracing::info!(
            entries = entries.len(),
            namespaces = namespaces.len(),
            "prepared finite native external notification clocks"
        );
        let projected = entries
            .iter()
            .map(|entry| entry.case.as_str())
            .collect::<BTreeSet<_>>();
        let inputs = windows
            .iter()
            .filter(|window| projected.contains(window.case.as_str()))
            .map(|window| {
                (
                    window.case.clone(),
                    window
                        .inputs
                        .iter()
                        .map(|(sequence, _)| *sequence)
                        .collect(),
                )
            })
            .collect();
        // Entries already retain the native clock and physical Source order.
        // A finite per-Case cursor avoids rescanning the whole run for every
        // delivery in high-volume notification streams.
        let mut pending = BTreeMap::<String, VecDeque<usize>>::new();
        for (index, entry) in entries.iter().enumerate() {
            pending
                .entry(entry.case.clone())
                .or_default()
                .push_back(index);
        }
        self.native_clock = NativeClock {
            namespaces,
            entries,
            pending,
            live: BTreeMap::new(),
            inputs,
        };
        Ok(())
    }
}

fn reserve_entry(entries: &mut Vec<Entry>, source_count: usize) -> Result<()> {
    // Every entry refers to one original finite slot. A long recording can
    // legitimately exceed 65536 slots; retain metadata without copying its
    // payload or imposing an unrelated fixed recording-length limit.
    ensure!(
        entries.len() < source_count,
        "native notification projection exceeds Source inventory"
    );
    entries
        .try_reserve(1)
        .context("cannot allocate native notification metadata")
}

#[allow(clippy::too_many_arguments)]
fn select(
    windows: &[source::Window],
    namespaces: &BTreeSet<String>,
    echoes: &echo::Echoes,
    record: &RecordedPush,
    slot: PushId,
    at: Option<DateTime<Utc>>,
    ordinal: usize,
    digest: Option<[u8; 32]>,
    namespace: Option<&str>,
    reference: Option<RecordRef>,
    inline: Vec<u8>,
) -> Result<Option<Entry>> {
    let Some(namespace) = namespace.filter(|ns| namespaces.contains(*ns)) else {
        return Ok(None);
    };
    let Some(digest) = digest else {
        return Ok(None);
    };
    if echoes.controls(record, Some(digest)) {
        return Ok(None);
    }
    let Some(at) = at else { return Ok(None) };
    let mut candidates = windows.iter().filter(|window| {
        (window.namespaces.is_empty() || window.namespaces.contains(namespace))
            && window.start.is_none_or(|start| at >= start)
            && window.end.is_none_or(|end| at < end)
    });
    let Some(window) = candidates.next() else {
        return Ok(None);
    };
    if candidates.next().is_some()
        || !window.selected
        || !window.projectable
        || window
            .connected_after
            .is_none_or(|connected| at < connected)
    {
        return Ok(None);
    }
    let start = window.start.context("native notification start missing")?;
    let offset = at - start;
    // Floor-millisecond input offsets cannot order a notification in that same millisecond.
    if window
        .inputs
        .iter()
        .any(|(_, input)| offset.num_milliseconds() == i64::try_from(*input).unwrap_or(i64::MAX))
    {
        return Ok(None);
    }
    let inputs_before = window
        .inputs
        .iter()
        .filter(|(_, input)| offset.num_milliseconds() > i64::try_from(*input).unwrap_or(i64::MAX))
        .map(|(sequence, _)| *sequence)
        .collect();
    let mut lifetime = window.end.context("native notification end missing")? - start;
    if let Some(at) = window.untracked_at_ms {
        lifetime =
            lifetime
                .min(chrono::TimeDelta::milliseconds(i64::try_from(at).context(
                    "native notification input offset exceeds clock range",
                )?));
    }
    if offset >= lifetime {
        return Ok(None);
    }
    let entry = Entry {
        case: window.case.clone(),
        namespace: namespace.into(),
        slot,
        anchor: (record.connection_id, record.subscription_sequence),
        reference,
        inline,
        source_at: at,
        offset,
        ordinal,
        digest,
        endpoint: endpoint(record),
        database: record.database,
        username: record.username.clone(),
        lifetime,
        inputs_before,
    };
    // Nonempty exclusions can name a dynamic Source socket. Without an
    // independent live identity proof, preserve the slot rather than sending
    // an exclusion that could address the wrong native client.
    let raw = entry.bytes()?;
    let frame = parse_pubsub_push(&raw)?.context("native notification is not a push")?;
    let broadcast = rpc::broadcast("PUBLISH", &[frame.channel, frame.payload])?
        .context("native notification is not an ordinary broadcast")?;
    let skip = &broadcast.value["skip_sid"];
    if !skip.is_null() && !skip.as_array().is_some_and(Vec::is_empty) {
        return Ok(None);
    }
    Ok(Some(entry))
}
