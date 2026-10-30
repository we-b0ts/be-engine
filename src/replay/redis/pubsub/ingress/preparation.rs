//! Prove the original ingress slot without changing Global ownership or payloads.
use super::*;

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
        if callbacks.is_empty() {
            return Ok(());
        }
        let wanted = callbacks
            .iter()
            .map(|c| c.key.clone())
            .collect::<HashSet<_>>();
        let mut candidates = HashMap::<Key, Vec<Candidate>>::new();
        for (index, push) in self.pushes.iter().enumerate() {
            if push.source != ReplaySource::Global || push.record.rpc_request.is_some() {
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
            if wanted.contains(&key) {
                candidates.entry(key).or_default().push(Candidate {
                    slot: PushId::Inline(index),
                    anchor: (push.record.connection_id, push.record.subscription_sequence),
                    frame: Frame {
                        reference: push.evidence.clone(),
                        inline: push.raw.clone(),
                    },
                    timestamp: push.record.timestamp,
                    ordinal: index,
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
                    if wanted.contains(&key) {
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
                            ordinal: entry.ordinal,
                        });
                    }
                }
            }
        }
        for callback in callbacks {
            let candidates = candidates.get(&callback.key).context(
                "remote Socket.IO callback has no original inbound request; refresh recording",
            )?;
            ensure!(
                candidates.len() == 1,
                "ambiguous original remote Socket.IO request"
            );
            let candidate = &candidates[0];
            if let Some(reference) = &candidate.frame.reference {
                let original: RecordedPush = reference.load()?;
                ensure!(
                    original.timestamp == candidate.timestamp
                        && (original.connection_id, original.subscription_sequence)
                            == candidate.anchor
                        && endpoint(&original) == callback.key.0,
                    "remote Socket.IO request metadata differs from original evidence"
                );
            }
            let timestamp = candidate
                .timestamp
                .context("remote Socket.IO request clock missing")?;
            ensure!(
                timestamp >= callback.case_started && timestamp <= callback.started,
                "remote Socket.IO request is outside its replying Case interval"
            );
            let raw = candidate.frame.bytes()?;
            let frame = parse_pubsub_push(&raw)?
                .context("remote Socket.IO request is not a notification")?;
            let identity = rpc::notification_request(&frame.channel, &frame.payload)
                .context("invalid original remote Socket.IO request")?;
            ensure!(
                frame.channel == callback.key.1 && identity == callback.key.2,
                "remote Socket.IO request metadata differs from its original bytes"
            );
            ensure!(
                self.ingress.slots.insert(candidate.slot),
                "one remote Socket.IO request cannot authorize multiple Case replies"
            );
            ensure!(
                self.ingress
                    .callbacks
                    .insert(callback.wire, self.ingress.entries.len())
                    .is_none(),
                "duplicate remote Socket.IO reply wire identity"
            );
            let prerequisites = causal::prerequisites(
                exchanges,
                &callback.case,
                &callback.key,
                callback.case_started,
                timestamp,
            )?;
            ensure!(
                self.ingress
                    .entries
                    .iter()
                    .map(|entry| entry.prerequisites.len())
                    .sum::<usize>()
                    + prerequisites.len()
                    <= 65536,
                "remote Socket.IO causal inventory exceeds bound"
            );
            self.ingress.entries.push(Entry {
                prerequisites,
                case: callback.case,
                source: identity,
                target_sid: None,
                endpoint: callback.key.0,
                channel: frame.channel,
                slot: candidate.slot,
                anchor: candidate.anchor,
                frame: candidate.frame.clone(),
                offset: timestamp - callback.case_started,
                ordinal: candidate.ordinal,
                reserved: false,
                delivered: false,
                failed: false,
            });
        }
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
            || exchange.record.command != "PUBLISH"
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
            result.len() < 4096,
            "remote Socket.IO request inventory exceeds bound"
        );
        ensure!(
            exchange.record.outcome == DependencyExchangeOutcome::Response
                && matches!(exchange.record.response_kind.as_str(), "integer" | "error")
                && exchange.record.replay_safe,
            "unsafe remote Socket.IO reply evidence"
        );
        result.push(Callback {
            case: case.into(),
            wire: (exchange.record.connection_id, exchange.record.sequence),
            key: (
                TargetKey {
                    host: normalize_host(&exchange.record.target_host),
                    port: exchange.record.target_port,
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
