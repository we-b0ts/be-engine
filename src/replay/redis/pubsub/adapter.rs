//! Socket.IO Redis-adapter correlation and identity translation, independent of application events.
use super::*;
use std::collections::HashMap;
type Realm = (TargetKey, i64, Option<String>);
type Scope = (bool, Option<String>);
type RequestKey = (Scope, Uuid, u64);
type SessionKey = (Realm, String, String);
#[derive(Debug, Default)]
pub(super) struct Bindings {
    hosts: HashMap<(Realm, String), String>,
    sessions: HashMap<SessionKey, String>,
    session_targets: HashMap<SessionKey, String>,
    callbacks: HashMap<(Realm, rpc::Identity), rpc::Identity>,
    callback_targets: HashMap<(Realm, rpc::Identity), rpc::Identity>,
    host_targets: HashMap<(Realm, String), String>,
    requests: HashMap<RequestKey, usize>,
    wire_references: std::collections::HashSet<(Uuid, u64)>,
    publishers: std::collections::HashSet<(Uuid, u64)>,
    callback_subscriptions: std::collections::HashSet<(Uuid, u64)>,
    unlinked: HashMap<Scope, usize>,
}
impl Bindings {
    pub(super) fn index(
        &mut self,
        record: &RecordedPush,
        source: ReplaySource,
        case_id: Option<&str>,
        index: usize,
    ) -> Result<()> {
        if let Some(request) = &record.rpc_request {
            let scope = if let Some(origin) = &request.case_id {
                ensure!(
                    source.is_run_level() || case_id == Some(origin.as_str()),
                    "RPC callback original case differs from its Case storage"
                );
                (true, Some(origin.clone()))
            } else {
                (source == ReplaySource::Case, case_id.map(str::to_owned))
            };
            ensure!(
                self.wire_references
                    .insert((request.connection_id, request.sequence)),
                "duplicate Redis RPC callback reference"
            );
            let key = (scope.clone(), request.connection_id, request.sequence);
            ensure!(
                !self.requests.contains_key(&key),
                "duplicate Redis RPC callback reference"
            );
            self.requests.insert(key, index);
            *self.unlinked.entry(scope).or_default() += 1;
        }
        Ok(())
    }
}
impl PubSubState {
    pub(in crate::replay::redis) fn link(
        &mut self,
        record: &RecordedExchange,
        source: ReplaySource,
        case_id: Option<&str>,
        args: &[Vec<u8>],
    ) -> Result<Option<usize>> {
        ensure!(
            record
                .rpc_callback_capture
                .as_deref()
                .is_none_or(|value| value == "bounded_window"),
            "unsupported Redis RPC callback capture contract"
        );
        if record.response_kind == "error" || record.outcome != DependencyExchangeOutcome::Response
        {
            return Ok(None);
        }
        let Some(request) = rpc::request(&record.command, args)? else {
            ensure!(
                record.rpc_callback_capture.is_none(),
                "RPC capture marker requires a supported RPC request"
            );
            if rpc::broadcast(&record.command, args)
                .ok()
                .flatten()
                .is_some()
            {
                self.echoes.register(record, args);
            }
            return Ok(None);
        };
        self.echoes.register(record, args);
        ensure!(
            self.bindings
                .publishers
                .insert((record.connection_id, record.sequence)),
            "duplicate Redis RPC publisher wire identity"
        );
        let scope = (source == ReplaySource::Case, case_id.map(str::to_owned));
        let index = self
            .bindings
            .requests
            .get(&(scope.clone(), record.connection_id, record.sequence))
            .copied();
        let Some(index) = index else {
            ensure!(
                !self
                    .bindings
                    .wire_references
                    .contains(&(record.connection_id, record.sequence)),
                "RPC callback original scope differs from its publisher"
            );
            ensure!(
                record.rpc_callback_capture.as_deref() == Some("bounded_window"),
                "Redis Pub/Sub RPC callback evidence missing; refresh the recording with callback capture enabled"
            );
            // A sealed modern window may contain no callback. Retain the finite
            // PUBLISH and its real Redis response; synthesize no RPC reply.
            return Ok(None);
        };
        let push = &mut self.pushes[index];
        ensure!(
            push.source == source
                || record.rpc_callback_capture.as_deref() == Some("bounded_window"),
            "cross-scope RPC callback requires a bounded-window publisher"
        );
        ensure!(!push.linked, "duplicate Redis RPC callback reference");
        ensure!(
            normalize_host(&push.record.target_host) == normalize_host(&record.target_host)
                && push.record.target_port == record.target_port,
            "RPC callback endpoint/session mismatch"
        );
        let raw = push.bytes()?;
        let frame = parse_pubsub_push(&raw)?.expect("validated push");
        ensure!(frame.channel == args[0], "RPC callback channel mismatch");
        let (identity, _) = rpc::callback(&frame.payload)?.expect("validated callback");
        ensure!(
            identity == request.identity,
            "RPC callback identity mismatch"
        );
        push.linked = true;
        self.bindings
            .callback_subscriptions
            .insert((push.record.connection_id, push.record.subscription_sequence));
        *self
            .bindings
            .unlinked
            .get_mut(&scope)
            .expect("indexed RPC scope") -= 1;
        Ok(Some(index))
    }

    pub(in crate::replay::redis) fn is_callback_subscription(
        &self,
        exchange: &ReplayExchange,
    ) -> bool {
        self.bindings
            .callback_subscriptions
            .contains(&(exchange.record.connection_id, exchange.record.sequence))
            || self.ingress.requires_subscription(exchange)
    }

    pub(in crate::replay) fn validate_links(
        &self,
        source: ReplaySource,
        case_id: Option<&str>,
    ) -> Result<()> {
        let scope = (source == ReplaySource::Case, case_id.map(str::to_owned));
        ensure!(
            self.bindings.unlinked.get(&scope).copied().unwrap_or(0) == 0,
            "orphan Redis RPC callback evidence"
        );
        Ok(())
    }

    pub(in crate::replay::redis) fn is_adapter_source(&self, exchange: &ReplayExchange) -> bool {
        self.ingress.owns_callback(exchange)
            || exchange.rpc_push.is_some()
            || exchange.record.rpc_callback_capture.as_deref() == Some("bounded_window")
            || rpc::broadcast(&exchange.record.command, &exchange.args)
                .ok()
                .flatten()
                .is_some()
    }

    #[cfg(test)]
    pub(in crate::replay::redis) fn matches(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<bool> {
        self.is_adapter_source(exchange).then(|| {
            self.comparison_args(exchange, args)
                .is_some_and(|comparison| comparison.source == comparison.actual)
        })
    }

    /// Translate protocol identities in private comparison copies only. Payload
    /// authorization remains with the selected request contracts.
    pub(in crate::replay::redis) fn comparison_args(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<RpcComparison> {
        if self.ingress.owns_callback(exchange) {
            return self.ingress.comparison(exchange, args);
        }
        if let Some((source, actual)) = self.compatible_broadcast(exchange, args) {
            return Some(RpcComparison {
                source: vec![
                    exchange.args[0].clone(),
                    serde_json::to_vec(&source.comparison_value(&actual)).ok()?,
                ],
                actual: vec![args[0].clone(), serde_json::to_vec(&actual.value).ok()?],
            });
        }
        let (source, actual) = self.compatible_request(exchange, args)?;
        Some(RpcComparison {
            source: vec![
                exchange.args[0].clone(),
                serde_json::to_vec(&source.comparison_value(&actual)).ok()?,
            ],
            actual: vec![args[0].clone(), serde_json::to_vec(&actual.value).ok()?],
        })
    }

    fn compatible_broadcast(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<(rpc::Broadcast, rpc::Broadcast)> {
        let mut source = rpc::broadcast(&exchange.record.command, &exchange.args)
            .ok()
            .flatten()?;
        let actual = rpc::broadcast(&exchange.record.command, args)
            .ok()
            .flatten()?;
        if source.value["room"] != actual.value["room"] {
            if !self.namespace_sessions.matches_room(
                exchange.case_id.as_deref(),
                &source.value["namespace"],
                &source.value["room"],
                &actual.value["room"],
            ) {
                return None;
            }
            source.value["room"] = actual.value["room"].clone();
        }
        let realm = (
            TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            exchange.record.database,
            exchange.record.username.clone(),
        );
        (exchange.args.first() == args.first()
            && source.envelope_matches(&actual)
            && self
                .bindings
                .hosts
                .get(&(realm.clone(), source.host.clone()))
                .is_none_or(|host| *host == actual.host)
            && self
                .bindings
                .host_targets
                .get(&(realm, actual.host.clone()))
                .is_none_or(|host| *host == source.host))
        .then_some((source, actual))
    }

    fn compatible_request(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<(rpc::Request, rpc::Request)> {
        if !self.is_adapter_source(exchange) {
            return None;
        }
        let source = rpc::request(&exchange.record.command, &exchange.args)
            .ok()
            .flatten()?;
        let actual = rpc::request(&exchange.record.command, args)
            .ok()
            .flatten()?;
        let realm = (
            TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            exchange.record.database,
            exchange.record.username.clone(),
        );
        (exchange.args.first() == args.first()
            && self
                .bindings
                .sessions
                .get(&(
                    realm.clone(),
                    source.identity.namespace.clone(),
                    source.identity.sid.clone(),
                ))
                .is_none_or(|sid| *sid == actual.identity.sid)
            && self
                .bindings
                .session_targets
                .get(&(
                    realm.clone(),
                    actual.identity.namespace.clone(),
                    actual.identity.sid.clone(),
                ))
                .is_none_or(|sid| *sid == source.identity.sid)
            && source.identity.namespace == actual.identity.namespace
            && source.envelope_matches(&actual)
            && self
                .bindings
                .callbacks
                .get(&(realm.clone(), source.identity.clone()))
                .is_none_or(|v| *v == actual.identity)
            && self
                .bindings
                .callback_targets
                .get(&(realm.clone(), actual.identity.clone()))
                .is_none_or(|bound| *bound == source.identity)
            && self
                .bindings
                .hosts
                .get(&(realm.clone(), source.identity.host.clone()))
                .is_none_or(|v| *v == actual.identity.host)
            && self
                .bindings
                .host_targets
                .get(&(realm.clone(), actual.identity.host.clone()))
                .is_none_or(|bound| *bound == source.identity.host))
        .then_some((source, actual))
    }

    pub(in crate::replay::redis) fn claim(
        &mut self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<Vec<u8>> {
        if !self.is_adapter_source(exchange) {
            return None;
        }
        if let Some((source, actual)) = self.compatible_broadcast(exchange, args) {
            let realm = (
                TargetKey {
                    host: normalize_host(&exchange.record.target_host),
                    port: exchange.record.target_port,
                },
                exchange.record.database,
                exchange.record.username.clone(),
            );
            self.bindings
                .hosts
                .insert((realm.clone(), source.host.clone()), actual.host.clone());
            self.bindings
                .host_targets
                .insert((realm, actual.host), source.host);
            return None;
        }
        let source = rpc::request(&exchange.record.command, &exchange.args)
            .ok()
            .flatten()?;
        let actual = rpc::request(&exchange.record.command, args)
            .ok()
            .flatten()?;
        let realm = (
            TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            exchange.record.database,
            exchange.record.username.clone(),
        );
        self.bindings.sessions.insert(
            (
                realm.clone(),
                source.identity.namespace.clone(),
                source.identity.sid.clone(),
            ),
            actual.identity.sid.clone(),
        );
        self.bindings.session_targets.insert(
            (
                realm.clone(),
                actual.identity.namespace.clone(),
                actual.identity.sid.clone(),
            ),
            source.identity.sid.clone(),
        );
        self.bindings.callback_targets.insert(
            (realm.clone(), actual.identity.clone()),
            source.identity.clone(),
        );
        self.bindings.host_targets.insert(
            (realm.clone(), actual.identity.host.clone()),
            source.identity.host.clone(),
        );
        self.bindings.callbacks.insert(
            (realm.clone(), source.identity.clone()),
            actual.identity.clone(),
        );
        self.bindings
            .hosts
            .insert((realm, source.identity.host), actual.identity.host.clone());
        let index = exchange.rpc_push?;
        let raw = self.pushes[index].bytes().ok()?;
        let frame = redis_command(&bytes::Bytes::copy_from_slice(&raw)).expect("validated push");
        let mut parts = frame.args;
        let (_, mut payload) = rpc::callback(parts.last().expect("push payload"))
            .ok()
            .flatten()
            .expect("validated callback");
        payload["host_id"] = actual.identity.host.into();
        payload["id"] = actual.identity.id.into();
        payload["sid"] = actual.identity.sid.into();
        *parts.last_mut().expect("push payload") =
            serde_json::to_vec(&payload).expect("JSON serializes");
        let name = frame.name.to_ascii_lowercase();
        let mut values = vec![name.as_bytes()];
        values.extend(parts.iter().map(Vec::as_slice));
        Some(crate::redis::encode_array(&values))
    }

    pub(in crate::replay::redis) fn rpc_is_detached(&self, matched: &MatchedRedisExchange) -> bool {
        // Link admission already proved this exact publisher and callback. The
        // Target may issue a Global request while any API happens to be active.
        matched
            .rpc_push
            .is_some_and(|index| self.pushes[index].source.is_run_level())
    }

    pub(in crate::replay::redis) fn rpc_delivery(
        &mut self,
        matched: &MatchedRedisExchange,
    ) -> Result<(u64, Delivery)> {
        let index = matched.rpc_push.context("missing RPC push")?;
        let push = &mut self.pushes[index];
        push.status = ReplayExchangeStatus::Responding;
        let bytes = matched
            .rpc_response
            .clone()
            .context("missing rendered RPC callback")?;
        Ok((
            push.record
                .duration_ms
                .saturating_sub(matched.publish_duration_ms),
            Delivery {
                case_id: None,
                push: PushId::Inline(index),
                bytes,
                matched: Some(matched.clone()),
                request_epoch: None,
            },
        ))
    }

    pub(in crate::replay::redis) fn rpc_sender(
        &self,
        matched: &MatchedRedisExchange,
    ) -> Result<mpsc::Sender<Delivery>> {
        let push = &self.pushes[matched.rpc_push.context("missing RPC push")?];
        let raw = push.bytes()?;
        let frame = parse_pubsub_push(&raw)?.expect("validated push");
        let mut subscriptions = self.subscriptions.iter().filter(|s| {
            !s.sender.is_closed()
                && s.source_connection == push.record.connection_id
                && s.sequence == push.record.subscription_sequence
                && s.target == matched.report.target
                && s.database == push.record.database
                && s.username == push.record.username
                && s.kind == frame.subscription_kind
                && s.subject == frame.subject
        });
        let sender = subscriptions
            .next()
            .context("RPC callback requires a confirmed matching subscriber at delivery")?
            .sender
            .clone();
        ensure!(
            subscriptions.next().is_none(),
            "ambiguous RPC callback subscribers"
        );
        Ok(sender)
    }
}
