//! Socket.IO Redis-adapter correlation and identity translation, independent of application events.
use super::*;
use std::collections::HashMap;
type Scope = (bool, Option<String>);
type RequestKey = (Scope, Uuid, u64);
#[derive(Debug, Default)]
pub(super) struct Bindings {
    identities: traffic_protocol_redis::pubsub::identity::Correspondences,
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
    pub(in crate::protocols::replay::redis) fn link(
        &mut self,
        record: &RecordedExchange,
        source: ReplaySource,
        case_id: Option<&str>,
        args: &[Vec<u8>],
    ) -> Result<Option<usize>> {
        ensure!(
            record
                .native
                .rpc_callback_capture
                .as_deref()
                .is_none_or(|value| value == "bounded_window"),
            "unsupported Redis RPC callback capture contract"
        );
        if record.native.response_kind == "error"
            || record.native.outcome != DependencyExchangeOutcome::Response
        {
            return Ok(None);
        }
        let Some(request) = rpc::request(&record.native.command, args)? else {
            ensure!(
                record.native.rpc_callback_capture.is_none(),
                "RPC capture marker requires a supported RPC request"
            );
            if rpc::broadcast(&record.native.command, args)
                .ok()
                .flatten()
                .is_some()
            {
                self.echoes.register(&record.native, args);
            }
            return Ok(None);
        };
        self.echoes.register(&record.native, args);
        ensure!(
            self.bindings
                .publishers
                .insert((record.native.connection_id, record.native.sequence)),
            "duplicate Redis RPC publisher wire identity"
        );
        let scope = (source == ReplaySource::Case, case_id.map(str::to_owned));
        let index = self
            .bindings
            .requests
            .get(&(
                scope.clone(),
                record.native.connection_id,
                record.native.sequence,
            ))
            .copied();
        let Some(index) = index else {
            ensure!(
                !self
                    .bindings
                    .wire_references
                    .contains(&(record.native.connection_id, record.native.sequence)),
                "RPC callback original scope differs from its publisher"
            );
            ensure!(
                record.native.rpc_callback_capture.as_deref() == Some("bounded_window"),
                "Redis Pub/Sub RPC callback evidence missing; refresh the recording with callback capture enabled"
            );
            // A sealed modern window may contain no callback. Retain the finite
            // PUBLISH and its real Redis response; synthesize no RPC reply.
            return Ok(None);
        };
        let push = &mut self.pushes[index];
        ensure!(
            push.source == source
                || record.native.rpc_callback_capture.as_deref() == Some("bounded_window"),
            "cross-scope RPC callback requires a bounded-window publisher"
        );
        ensure!(!push.linked, "duplicate Redis RPC callback reference");
        ensure!(
            normalize_host(&push.record.target_host) == normalize_host(&record.native.target_host)
                && push.record.target_port == record.native.target_port,
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

    pub(in crate::protocols::replay::redis) fn is_callback_subscription(
        &self,
        exchange: &ReplayExchange,
    ) -> bool {
        self.bindings.callback_subscriptions.contains(&(
            exchange.record.native.connection_id,
            exchange.record.native.sequence,
        )) || self.ingress.requires_subscription(exchange)
    }

    pub(crate) fn validate_links(&self, source: ReplaySource, case_id: Option<&str>) -> Result<()> {
        let scope = (source == ReplaySource::Case, case_id.map(str::to_owned));
        ensure!(
            self.bindings.unlinked.get(&scope).copied().unwrap_or(0) == 0,
            "orphan Redis RPC callback evidence"
        );
        Ok(())
    }

    pub(in crate::protocols::replay::redis) fn is_adapter_source(
        &self,
        exchange: &ReplayExchange,
    ) -> bool {
        self.ingress.owns_callback(exchange)
            || exchange.rpc_push.is_some()
            || exchange.record.native.rpc_callback_capture.as_deref() == Some("bounded_window")
            || rpc::broadcast(&exchange.record.native.command, &exchange.args)
                .ok()
                .flatten()
                .is_some()
    }

    #[cfg(test)]
    pub(in crate::protocols::replay::redis) fn matches(
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
    pub(in crate::protocols::replay::redis) fn comparison_args(
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
        self.bindings.identities.compatible_broadcast(
            &exchange.record.native,
            &exchange.args,
            args,
            |namespace, source, actual| {
                self.namespace_sessions.matches_sid(
                    exchange.case_id.as_deref(),
                    namespace,
                    source,
                    actual,
                )
            },
        )
    }

    fn compatible_request(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<(rpc::Request, rpc::Request)> {
        self.is_adapter_source(exchange).then_some(())?;
        self.bindings
            .identities
            .compatible_request(&exchange.record.native, &exchange.args, args)
    }

    pub(in crate::protocols::replay::redis) fn claim(
        &mut self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<Vec<u8>> {
        if !self.is_adapter_source(exchange) {
            return None;
        }
        if let Some((source, actual)) = self.compatible_broadcast(exchange, args) {
            self.bindings
                .identities
                .bind_broadcast(&exchange.record.native, source, actual);
            return None;
        }
        let source = rpc::request(&exchange.record.native.command, &exchange.args)
            .ok()
            .flatten()?;
        let actual = rpc::request(&exchange.record.native.command, args)
            .ok()
            .flatten()?;
        self.bindings.identities.bind_request(
            &exchange.record.native,
            source.identity,
            &actual.identity,
        );
        let index = exchange.rpc_push?;
        let raw = self.pushes[index].bytes().ok()?;
        traffic_protocol_redis::pubsub::identity::render_callback(&raw, &actual.identity).ok()
    }

    pub(in crate::protocols::replay::redis) fn rpc_is_detached(
        &self,
        matched: &MatchedRedisExchange,
    ) -> bool {
        // Link admission already proved this exact publisher and callback. The
        // Target may issue a Global request while any API happens to be active.
        matched
            .rpc_push
            .is_some_and(|index| self.pushes[index].source.is_run_level())
    }

    pub(in crate::protocols::replay::redis) fn rpc_delivery(
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
                value: None,
            },
        ))
    }

    pub(in crate::protocols::replay::redis) fn rpc_sender(
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
