//! Exact ownership selectors for incoming Redis notifications, never commands.
use anyhow::{Result, ensure};
use base64::Engine as _;
use serde_json::Value;

use crate::policy::Database;
use crate::policy::native::{RedisPubsubKind, RedisPubsubSelector};
use crate::protocols::recording::events::RedisPubSubPushEvent;
use crate::redis::{RedisPubSubPush, RedisSubscriptionKind, parse_pubsub_push};

pub(crate) fn anchor(event: &Value) -> Option<(uuid::Uuid, u64)> {
    Some((
        event["connection_id"].as_str()?.parse().ok()?,
        event["subscription_sequence"].as_u64()?,
    ))
}

pub(crate) fn capture(value: &Value) -> Option<Vec<u8>> {
    if value["truncated"] == true {
        return None;
    }
    let data = value["data"].as_str()?;
    if data.len() > 2 * crate::value_limits::MAX_VALUE_BYTES {
        return None;
    }
    let bytes = match value["encoding"].as_str()? {
        "utf8" => data.as_bytes().to_vec(),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(data)
            .ok()?,
        _ => return None,
    };
    (bytes.len() <= crate::value_limits::MAX_VALUE_BYTES
        && ["stored_len", "original_len"].iter().all(|name| {
            value[*name].is_null() || value[*name].as_u64() == Some(bytes.len() as u64)
        }))
    .then_some(bytes)
}

pub(crate) fn subscription_identity(event: &Value) -> Option<(uuid::Uuid, u64)> {
    (event["event_type"] == "redis_exchange"
        && matches!(
            event["command"].as_str(),
            Some("SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE")
        ))
    .then(|| {
        Some((
            event["connection_id"].as_str()?.parse().ok()?,
            event["sequence"].as_u64()?,
        ))
    })?
}

pub(crate) fn validate_subscription(
    selector: &RedisPubsubSelector,
    push: &Value,
    subscription: &Value,
) -> Result<()> {
    let input_anchor =
        anchor(push).ok_or_else(|| anyhow::anyhow!("Source Pub/Sub input anchor is invalid"))?;
    ensure!(
        input_anchor.1 > 0 && Some(input_anchor) == subscription_identity(subscription),
        "Source Pub/Sub input lacks its original subscription anchor"
    );
    ensure!(
        subscription["replay_safe"] == true
            && subscription["outcome"] == "response"
            && (subscription["username"].is_null() || subscription["username"].is_string()),
        "Source Pub/Sub subscription is unsafe or incomplete"
    );
    ensure!(
        subscription["target_host"]
            .as_str()
            .zip(
                subscription["target_port"]
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok())
            )
            .zip(subscription["database"].as_i64())
            .is_some_and(|((host, port), db)| realm(
                selector,
                host,
                port,
                db,
                subscription["username"].as_str()
            )),
        "Source Pub/Sub subscription realm differs from the received input"
    );
    let command = match selector.kind {
        RedisPubsubKind::Message => "SUBSCRIBE",
        RedisPubsubKind::Pmessage => "PSUBSCRIBE",
        RedisPubsubKind::Smessage => "SSUBSCRIBE",
    };
    ensure!(
        subscription["command"] == command,
        "Source Pub/Sub subscription kind differs from the received input"
    );
    let args = subscription["args"]
        .as_array()
        .and_then(|args| args.iter().map(capture).collect::<Option<Vec<_>>>())
        .ok_or_else(|| anyhow::anyhow!("Source Pub/Sub subscription arguments are incomplete"))?;
    ensure!(
        args.len() == 1
            && args[0]
                == selector
                    .pattern
                    .as_deref()
                    .unwrap_or(&selector.channel)
                    .as_bytes(),
        "Source Pub/Sub subscription subject differs from the received input"
    );
    let response = capture(&subscription["response"])
        .ok_or_else(|| anyhow::anyhow!("Source Pub/Sub subscription confirmation is incomplete"))?;
    crate::redis::validate_subscription_confirmation(
        &crate::redis::RedisCommand {
            name: command.into(),
            args,
        },
        &response,
    )
}

pub(crate) fn validate(selector: &RedisPubsubSelector) -> Result<()> {
    traffic_policy_compiler::validation::pubsub(selector)
}

fn realm(
    selector: &RedisPubsubSelector,
    host: &str,
    port: u16,
    db: i64,
    user: Option<&str>,
) -> bool {
    selector.resource.endpoint.host.eq_ignore_ascii_case(host)
        && selector.resource.endpoint.port == port
        && selector
            .resource
            .database
            .as_ref()
            .and_then(Database::index)
            == Some(db)
        && selector.resource.username.as_deref() == user
}

fn frame(selector: &RedisPubsubSelector, raw: &[u8]) -> bool {
    parse_pubsub_push(raw)
        .ok()
        .flatten()
        .is_some_and(|push| matches_frame(selector, &push))
}

fn matches_frame(selector: &RedisPubsubSelector, push: &RedisPubSubPush) -> bool {
    let kind = match selector.kind {
        RedisPubsubKind::Message => RedisSubscriptionKind::Channel,
        RedisPubsubKind::Pmessage => RedisSubscriptionKind::Pattern,
        RedisPubsubKind::Smessage => RedisSubscriptionKind::ShardChannel,
    };
    push.subscription_kind == kind
        && push.channel == selector.channel.as_bytes()
        && push.subject
            == selector
                .pattern
                .as_deref()
                .unwrap_or(&selector.channel)
                .as_bytes()
}

pub(crate) fn matches_record(selector: &RedisPubsubSelector, event: &RedisPubSubPushEvent) -> bool {
    event.replay_safe
        && !event.response.truncated
        && event.subscription_sequence > 0
        && event.rpc_request.is_none()
        && realm(
            selector,
            &event.target_host,
            event.target_port,
            event.database,
            event.username.as_deref(),
        )
        && super::decode_capture(&event.response).is_some_and(|raw| frame(selector, &raw))
}

pub(crate) fn matches_value(selector: &RedisPubsubSelector, event: &Value) -> bool {
    if event["event_type"] != "redis_pub_sub_push"
        || event["replay_safe"] != true
        || !event["rpc_request"].is_null()
        || !(event["username"].is_null() || event["username"].is_string())
        || !event["subscription_sequence"]
            .as_u64()
            .is_some_and(|n| n > 0)
        || event["connection_id"]
            .as_str()
            .and_then(|id| id.parse::<uuid::Uuid>().ok())
            .is_none()
    {
        return false;
    }
    let Some((host, port, db)) = event["target_host"]
        .as_str()
        .zip(
            event["target_port"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok()),
        )
        .zip(event["database"].as_i64())
        .map(|((host, port), db)| (host, port, db))
    else {
        return false;
    };
    realm(selector, host, port, db, event["username"].as_str())
        && capture(&event["response"]).is_some_and(|raw| frame(selector, &raw))
}

#[cfg(test)]
mod tests;
