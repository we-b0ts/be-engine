//! Bijective Socket.IO manager, namespace-session and callback identities.
use crate::{recorded::RecordedExchange, redis_command, socketio_rpc as rpc};
use anyhow::{Context, Result};
use std::collections::HashMap;
use traffic_protocol::{connection::Endpoint, observation::normalize_host};

type Realm = (Endpoint, i64, Option<String>);
type SessionKey = (Realm, String, String);

#[derive(Debug, Default)]
pub struct Correspondences {
    hosts: HashMap<(Realm, String), String>,
    sessions: HashMap<SessionKey, String>,
    session_targets: HashMap<SessionKey, String>,
    callbacks: HashMap<(Realm, rpc::Identity), rpc::Identity>,
    callback_targets: HashMap<(Realm, rpc::Identity), rpc::Identity>,
    host_targets: HashMap<(Realm, String), String>,
}

impl Correspondences {
    pub fn compatible_broadcast(
        &self,
        record: &RecordedExchange,
        source_args: &[Vec<u8>],
        args: &[Vec<u8>],
        matches_sid: impl Fn(&serde_json::Value, &serde_json::Value, &serde_json::Value) -> bool,
    ) -> Option<(rpc::Broadcast, rpc::Broadcast)> {
        let mut source = rpc::broadcast(&record.command, source_args)
            .ok()
            .flatten()?;
        let actual = rpc::broadcast(&record.command, args).ok().flatten()?;
        for field in ["room", "skip_sid"] {
            if source.value[field] == actual.value[field] {
                continue;
            }
            if !matches_sid(
                &source.value["namespace"],
                &source.value[field],
                &actual.value[field],
            ) {
                return None;
            }
            source.value[field] = actual.value[field].clone();
        }
        let realm = (
            Endpoint {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            },
            record.database,
            record.username.clone(),
        );
        (source_args.first() == args.first()
            && source.envelope_matches(&actual)
            && self
                .hosts
                .get(&(realm.clone(), source.host.clone()))
                .is_none_or(|host| *host == actual.host)
            && self
                .host_targets
                .get(&(realm, actual.host.clone()))
                .is_none_or(|host| *host == source.host))
        .then_some((source, actual))
    }

    pub fn compatible_request(
        &self,
        record: &RecordedExchange,
        source_args: &[Vec<u8>],
        args: &[Vec<u8>],
    ) -> Option<(rpc::Request, rpc::Request)> {
        let source = rpc::request(&record.command, source_args).ok().flatten()?;
        let actual = rpc::request(&record.command, args).ok().flatten()?;
        let realm = (
            Endpoint {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            },
            record.database,
            record.username.clone(),
        );
        (source_args.first() == args.first()
            && self
                .sessions
                .get(&(
                    realm.clone(),
                    source.identity.namespace.clone(),
                    source.identity.sid.clone(),
                ))
                .is_none_or(|sid| *sid == actual.identity.sid)
            && self
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
                .callbacks
                .get(&(realm.clone(), source.identity.clone()))
                .is_none_or(|v| *v == actual.identity)
            && self
                .callback_targets
                .get(&(realm.clone(), actual.identity.clone()))
                .is_none_or(|bound| *bound == source.identity)
            && self
                .hosts
                .get(&(realm.clone(), source.identity.host.clone()))
                .is_none_or(|v| *v == actual.identity.host)
            && self
                .host_targets
                .get(&(realm.clone(), actual.identity.host.clone()))
                .is_none_or(|bound| *bound == source.identity.host))
        .then_some((source, actual))
    }

    pub fn bind_broadcast(
        &mut self,
        record: &RecordedExchange,
        source: rpc::Broadcast,
        actual: rpc::Broadcast,
    ) {
        let realm = (
            Endpoint {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            },
            record.database,
            record.username.clone(),
        );
        self.hosts
            .insert((realm.clone(), source.host.clone()), actual.host.clone());
        self.host_targets.insert((realm, actual.host), source.host);
    }

    pub fn bind_request(
        &mut self,
        record: &RecordedExchange,
        source: rpc::Identity,
        actual: &rpc::Identity,
    ) {
        let realm = (
            Endpoint {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            },
            record.database,
            record.username.clone(),
        );
        self.sessions.insert(
            (realm.clone(), source.namespace.clone(), source.sid.clone()),
            actual.sid.clone(),
        );
        self.session_targets.insert(
            (realm.clone(), actual.namespace.clone(), actual.sid.clone()),
            source.sid.clone(),
        );
        self.callback_targets
            .insert((realm.clone(), actual.clone()), source.clone());
        self.host_targets
            .insert((realm.clone(), actual.host.clone()), source.host.clone());
        self.callbacks
            .insert((realm.clone(), source.clone()), actual.clone());
        self.hosts.insert((realm, source.host), actual.host.clone());
    }
}

pub fn render_callback(raw: &[u8], actual: &rpc::Identity) -> Result<Vec<u8>> {
    let frame = redis_command(&bytes::Bytes::copy_from_slice(raw))?;
    let mut parts = frame.args;
    let (_, mut payload) = rpc::callback(parts.last().context("RPC push payload missing")?)?
        .context("RPC push is not a callback")?;
    payload["host_id"] = actual.host.clone().into();
    payload["id"] = actual.id.into();
    payload["sid"] = actual.sid.clone().into();
    *parts.last_mut().expect("push payload") = serde_json::to_vec(&payload)?;
    let name = frame.name.to_ascii_lowercase();
    let mut values = vec![name.as_bytes()];
    values.extend(parts.iter().map(Vec::as_slice));
    Ok(crate::encode_array(&values))
}

#[cfg(test)]
mod tests;
