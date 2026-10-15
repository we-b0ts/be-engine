//! Socket.IO Redis-adapter correlation and identity translation, independent of application events.
use super::*;
use std::collections::HashMap;
type Realm = (TargetKey, i64, Option<String>);
type Scope = (bool, Option<String>);
type RequestKey = (Scope, Uuid, u64);
#[derive(Debug, Default)]
pub(super) struct Bindings {
    hosts: HashMap<(Realm, String), String>,
    callbacks: HashMap<(Realm, rpc::Identity), rpc::Identity>,
    callback_targets: HashMap<(Realm, rpc::Identity), rpc::Identity>,
    host_targets: HashMap<(Realm, String), String>,
    requests: HashMap<RequestKey, usize>,
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
            let scope = (source == ReplaySource::Case, case_id.map(str::to_owned));
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
        if record.response_kind == "error" || record.outcome != DependencyExchangeOutcome::Response
        {
            return Ok(None);
        }
        let Some(request) = rpc::request(&record.command, args)? else {
            return Ok(None);
        };
        let scope = (source == ReplaySource::Case, case_id.map(str::to_owned));
        let index = *self.bindings.requests.get(&(scope.clone(), record.connection_id, record.sequence))
            .context("Redis Pub/Sub RPC callback evidence missing; refresh the recording with callback capture enabled")?;
        let push = &mut self.pushes[index];
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
        *self
            .bindings
            .unlinked
            .get_mut(&scope)
            .expect("indexed RPC scope") -= 1;
        Ok(Some(index))
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

    pub(in crate::replay::redis) fn matches(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<bool> {
        exchange.rpc_push?;
        let source = rpc::request(&exchange.record.command, &exchange.args)
            .ok()
            .flatten()?;
        let Some(actual) = rpc::request(&exchange.record.command, args).ok().flatten() else {
            return Some(false);
        };
        let realm = (
            TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            exchange.record.database,
            exchange.record.username.clone(),
        );
        Some(
            exchange.args.first() == args.first()
                && source.matches(&actual)
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
                    .is_none_or(|bound| *bound == source.identity.host),
        )
    }

    pub(in crate::replay::redis) fn claim(
        &mut self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<Vec<u8>> {
        let index = exchange.rpc_push?;
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
        let raw = self.pushes[index].bytes().ok()?;
        let frame = redis_command(&bytes::Bytes::copy_from_slice(&raw)).expect("validated push");
        let mut parts = frame.args;
        let (_, mut payload) = rpc::callback(parts.last().expect("push payload"))
            .ok()
            .flatten()
            .expect("validated callback");
        payload["host_id"] = actual.identity.host.into();
        payload["id"] = actual.identity.id.into();
        *parts.last_mut().expect("push payload") =
            serde_json::to_vec(&payload).expect("JSON serializes");
        let name = frame.name.to_ascii_lowercase();
        let mut values = vec![name.as_bytes()];
        values.extend(parts.iter().map(Vec::as_slice));
        Some(crate::redis::encode_array(&values))
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
                push: PushId::Inline(index),
                bytes,
                matched: Some(matched.clone()),
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
