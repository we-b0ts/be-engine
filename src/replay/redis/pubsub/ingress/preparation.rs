//! Prove the original ingress slot without changing Global ownership or payloads.
use super::*;

const MAX_ENTRIES: usize = 4096;
const MAX_PREREQUISITES: usize = 65536;

struct Callback {
    case: String,
    wire: Wire,
    key: Key,
    started: DateTime<Utc>,
    case_started: DateTime<Utc>,
}

struct Candidate {
    slot: PushId,
    anchor: Wire,
    frame: Frame,
    timestamp: Option<DateTime<Utc>>,
    ordinal: usize,
}

impl Candidate {
    fn validate(&self, key: &Key) -> Result<rpc::Request> {
        let raw = if let Some(reference) = &self.frame.reference {
            let original: RecordedPush = reference.load()?;
            ensure!(
                original.timestamp == self.timestamp
                    && (original.connection_id, original.subscription_sequence) == self.anchor
                    && endpoint(&original) == key.0,
                "remote Socket.IO request metadata differs from original evidence"
            );
            original.response.decode()?
        } else {
            self.frame.inline.clone()
        };
        let frame =
            parse_pubsub_push(&raw)?.context("remote Socket.IO request is not a notification")?;
        ensure!(
            frame.channel == key.1,
            "remote Socket.IO request channel differs from its original bytes"
        );
        let request = rpc::request("PUBLISH", &[frame.channel, frame.payload])?
            .context("invalid original remote Socket.IO request")?;
        ensure!(
            request.identity == key.2,
            "remote Socket.IO request identity differs from its original bytes"
        );
        Ok(request)
    }

    fn entry(
        &self,
        key: Key,
        case: String,
        started: DateTime<Utc>,
        reply: Option<Wire>,
        exchanges: &[ReplayExchange],
    ) -> Result<Entry> {
        let at = self
            .timestamp
            .context("remote Socket.IO request clock missing")?;
        let prerequisites = causal::prerequisites(exchanges, &case, &key, started, at)?;
        Ok(Entry {
            case,
            source: key.2,
            reply,
            target_sid: None,
            endpoint: key.0,
            channel: key.1,
            slot: self.slot,
            anchor: self.anchor,
            frame: self.frame.clone(),
            offset: at - started,
            ordinal: self.ordinal,
            reserved: false,
            delivered_at: None,
            failed: false,
            prerequisites,
        })
    }
}

impl super::super::super::RedisReplayState {
    pub(in crate::replay) fn prepare_ingress(
        &mut self,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<()> {
        self.pubsub.prepare_ingress(&self.exchanges, cases)
    }
}

impl PubSubState {
    pub(in crate::replay::redis) fn prepare_ingress(
        &mut self,
        exchanges: &[ReplayExchange],
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<()> {
        let callbacks = callbacks(exchanges, cases)?;
        let rooms = unanswered::Rooms::prepare(exchanges, &self.namespace_sessions);
        if callbacks.is_empty() && rooms.is_empty() {
            return Ok(());
        }
        let wanted = callbacks
            .iter()
            .map(|c| c.key.clone())
            .collect::<HashSet<_>>();
        let mut candidates = HashMap::<Key, Vec<Candidate>>::new();
        for (index, push) in self.pushes.iter().enumerate() {
            if !push.source.is_run_level() || push.record.rpc_request.is_some() {
                continue;
            }
            let raw = push.bytes()?;
            let Some(frame) = parse_pubsub_push(&raw)? else {
                continue;
            };
            let Some(identity) = rpc::notification_request(&frame.channel, &frame.payload) else {
                continue;
            };
            let key = (endpoint(&push.record), frame.channel, identity);
            if wanted.contains(&key)
                || (rooms
                    .find(&key, push.record.timestamp, push.source)
                    .is_some()
                    && !self
                        .echoes
                        .controls(&push.record, rpc::echo_digest(&key.1, &frame.payload)))
            {
                candidates.entry(key).or_default().push(Candidate {
                    slot: PushId::Inline(index),
                    anchor: (push.record.connection_id, push.record.subscription_sequence),
                    frame: Frame {
                        reference: push.evidence.clone(),
                        inline: push.raw.clone(),
                    },
                    timestamp: push.record.timestamp,
                    ordinal: push
                        .evidence
                        .as_ref()
                        .map_or(index, |reference| reference.location.line),
                });
            }
        }
        for (lane_index, lane) in self.indexed.lanes.iter().enumerate() {
            let pages = lane
                .pages
                .as_ref()
                .context("ingress notification inventory is not sealed")?;
            for page in 0..pages.pages() {
                for (offset, entry) in pages.read_page(page)?.into_iter().enumerate() {
                    let Some((channel, identity)) = entry.adapter_request else {
                        continue;
                    };
                    let key = (endpoint(&lane.record), channel, identity);
                    if wanted.contains(&key)
                        || (rooms
                            .find(&key, entry.timestamp, lane.source_kind)
                            .is_some()
                            && !self.echoes.controls(&lane.record, entry.adapter_echo))
                    {
                        let ordinal = entry.location.line;
                        candidates.entry(key).or_default().push(Candidate {
                            slot: PushId::Indexed {
                                lane: lane_index,
                                index: pages.page_start(page) + offset,
                            },
                            anchor: (lane.record.connection_id, lane.record.subscription_sequence),
                            frame: Frame {
                                reference: Some(lane.source.reference(entry.location)),
                                inline: vec![],
                            },
                            timestamp: entry.timestamp,
                            ordinal,
                        });
                    }
                }
            }
        }
        let mut prerequisite_count = 0;
        for callback in callbacks {
            let candidates = candidates.get(&callback.key).context(
                "remote Socket.IO callback has no original inbound request; refresh recording",
            )?;
            ensure!(
                candidates.len() == 1,
                "ambiguous original remote Socket.IO request"
            );
            let candidate = &candidates[0];
            let timestamp = candidate
                .timestamp
                .context("remote Socket.IO request clock missing")?;
            ensure!(
                timestamp >= callback.case_started && timestamp <= callback.started,
                "remote Socket.IO request is outside its replying Case interval"
            );
            candidate.validate(&callback.key)?;
            let entry = candidate.entry(
                callback.key,
                callback.case,
                callback.case_started,
                Some(callback.wire),
                exchanges,
            )?;
            self.ingress.register(entry, &mut prerequisite_count)?;
        }
        let replies = self.ingress.entries.len();
        for (key, candidates) in candidates {
            if wanted.contains(&key) {
                continue;
            }
            let [candidate] = candidates.as_slice() else {
                continue;
            };
            // Only original Process records without an echo or reply entered this inventory.
            let Some(room) = rooms.find(&key, candidate.timestamp, ReplaySource::Process) else {
                continue;
            };
            if !candidate.validate(&key)?.value["skip_sid"].is_null() {
                continue;
            }
            let entry = candidate.entry(
                key,
                room.case.to_owned(),
                room.window.start,
                None,
                exchanges,
            )?;
            if !entry.prerequisites.is_empty() {
                self.ingress.register(entry, &mut prerequisite_count)?;
            }
        }
        tracing::info!(
            replies,
            unanswered = self.ingress.entries.len() - replies,
            "prepared finite Socket.IO Redis ingress"
        );
        Ok(())
    }
}

impl Ingress {
    fn register(&mut self, entry: Entry, prerequisite_count: &mut usize) -> Result<()> {
        *prerequisite_count += entry.prerequisites.len();
        ensure!(
            *prerequisite_count <= MAX_PREREQUISITES && self.entries.len() < MAX_ENTRIES,
            "remote Socket.IO ingress inventory exceeds bound"
        );
        ensure!(
            self.slots.insert(entry.slot),
            "one remote Socket.IO request cannot authorize multiple deliveries"
        );
        if let Some(wire) = entry.reply {
            ensure!(
                self.callbacks.insert(wire, self.entries.len()).is_none(),
                "duplicate remote Socket.IO reply wire identity"
            );
        }
        self.entries.push(entry);
        Ok(())
    }
}

fn endpoint(record: &RecordedPush) -> TargetKey {
    TargetKey {
        host: normalize_host(&record.target_host),
        port: record.target_port,
    }
}

fn callbacks(
    exchanges: &[ReplayExchange],
    cases: &BTreeMap<String, ReplayCase>,
) -> Result<Vec<Callback>> {
    let mut result = Vec::new();
    let mut starts = HashMap::<String, Option<DateTime<Utc>>>::new();
    for exchange in exchanges {
        if exchange.source != ReplaySource::Case
            || exchange.shared_rule_id.is_some()
            || exchange.record.native.command != "PUBLISH"
            || exchange.args.len() != 2
        {
            continue;
        }
        let Some((identity, _)) = rpc::callback(&exchange.args[1]).ok().flatten() else {
            continue;
        };
        let case = exchange
            .case_id
            .as_deref()
            .context("remote Socket.IO reply has no Case")?;
        if !starts.contains_key(case) {
            let dir = &cases
                .get(case)
                .context("remote Socket.IO reply Case missing")?
                .dir;
            let path = dir.join("request.json");
            if !path.is_file() {
                starts.insert(case.into(), None);
                continue;
            }
            let raw = std::fs::read(path)?;
            let request =
                crate::json_value::parse(&raw).context("invalid remote Socket.IO Case request")?;
            let start = if request["interaction"]["protocol"] == "socket_io" {
                Some(serde_json::from_value(request["timestamp"].clone())?)
            } else {
                None
            };
            starts.insert(case.into(), start);
        }
        let Some(case_started) = starts[case] else {
            continue;
        };
        ensure!(
            result.len() < MAX_ENTRIES,
            "remote Socket.IO request inventory exceeds bound"
        );
        ensure!(
            exchange.record.native.outcome == DependencyExchangeOutcome::Response
                && matches!(
                    exchange.record.native.response_kind.as_str(),
                    "integer" | "error"
                )
                && exchange.record.native.replay_safe,
            "unsafe remote Socket.IO reply evidence"
        );
        result.push(Callback {
            case: case.into(),
            wire: (
                exchange.record.native.connection_id,
                exchange.record.native.sequence,
            ),
            key: (
                TargetKey {
                    host: normalize_host(&exchange.record.native.target_host),
                    port: exchange.record.native.target_port,
                },
                exchange.args[0].clone(),
                identity,
            ),
            started: exchange
                .record
                .earliest_start()
                .context("remote Socket.IO reply clock missing")?,
            case_started,
        });
    }
    Ok(result)
}
