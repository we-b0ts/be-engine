//! Native RESP2 confirmations own subscription subjects and lifetimes.
use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use redis_protocol::resp2::types::BytesFrame;
use traffic_model::recording::ProtocolRef;

use crate::{RedisCommand, RedisFrameKind, RedisSubscriptionKind};

type Subject = (RedisSubscriptionKind, Bytes);

#[derive(Clone)]
pub(super) struct Subscription<A> {
    pub target: Vec<u8>,
    pub anchor: A,
}

pub(super) struct Subscriptions<A>(HashMap<Subject, Subscription<A>>);

impl<A> Default for Subscriptions<A> {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

impl<A> Subscriptions<A> {
    pub fn active(&self) -> bool {
        !self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn get(&self, kind: RedisSubscriptionKind, subject: &Bytes) -> Option<&Subscription<A>> {
        self.0.get(&(kind, subject.clone()))
    }

    pub fn confirmation(
        &self,
        command: &RedisCommand,
        raw: &Bytes,
        replay: bool,
    ) -> Result<Option<Confirmation>> {
        use RedisSubscriptionKind::{Channel, Pattern, ShardChannel};

        let (kind, remove) = match command.name.as_str() {
            "SUBSCRIBE" => (Channel, false),
            "UNSUBSCRIBE" => (Channel, true),
            "PSUBSCRIBE" => (Pattern, false),
            "PUNSUBSCRIBE" => (Pattern, true),
            "SSUBSCRIBE" => (ShardChannel, false),
            "SUNSUBSCRIBE" => (ShardChannel, true),
            _ => return Ok(None),
        };
        if crate::frame_kind(raw)? == RedisFrameKind::Error {
            return Ok(None);
        }
        let [target] = command.args.as_slice() else {
            anyhow::bail!("Redis subscription requires one explicit subject");
        };
        let (BytesFrame::Array(items), length) = redis_protocol::resp2::decode::decode_bytes(raw)?
            .context("incomplete Redis subscription confirmation")?
        else {
            anyhow::bail!("Redis subscription confirmation is not an array");
        };
        let [
            _,
            BytesFrame::BulkString(source) | BytesFrame::SimpleString(source),
            BytesFrame::Integer(count),
        ] = items.as_slice()
        else {
            anyhow::bail!("Redis subscription confirmation has invalid framing");
        };
        ensure!(
            length == raw.len(),
            "Redis subscription confirmation has trailing bytes"
        );
        let source_command = RedisCommand {
            name: command.name.clone(),
            args: vec![source.to_vec()],
        };
        crate::validate_subscription_confirmation(&source_command, raw)?;
        let source_key = (kind, Bytes::copy_from_slice(source));
        let existing = self.0.get(&source_key);
        let active = self
            .0
            .keys()
            .filter(|(item, _)| (*item == ShardChannel) == (kind == ShardChannel))
            .count();
        let expected = if remove {
            active - usize::from(existing.is_some())
        } else {
            active + usize::from(existing.is_none())
        };
        ensure!(
            usize::try_from(*count)? == expected,
            "Redis subscription confirmation count differs from its active session"
        );
        ensure!(
            remove || existing.is_some() || self.0.len() < 256,
            "Redis session exceeds the active subscription limit"
        );
        ensure!(
            existing.is_none_or(|existing| existing.target == *target)
                && !self.0.iter().any(|(key, binding)| key.0 == kind
                    && *key != source_key
                    && binding.target == *target),
            "Redis subscription subjects do not map one-to-one"
        );
        let output = if source.as_ref() == target {
            raw.clone()
        } else {
            ensure!(
                replay && kind != Pattern,
                "Redis subscription confirmation changed its subject"
            );
            crate::translate_subscription_confirmation(&source_command, raw, target)?.into()
        };
        Ok(Some(Confirmation {
            source: source_key,
            target: target.clone(),
            remove,
            output,
        }))
    }

    pub fn apply(&mut self, confirmation: Confirmation, anchor: Option<A>) -> Result<()> {
        if confirmation.remove {
            self.0.remove(&confirmation.source);
        } else {
            let anchor = anchor.context("Redis confirmation has no delivery anchor")?;
            self.0.insert(
                confirmation.source,
                Subscription {
                    target: confirmation.target,
                    anchor,
                },
            );
        }
        Ok(())
    }
}

impl Subscriptions<ProtocolRef> {
    pub fn anchors(&self) -> Vec<ProtocolRef> {
        self.0
            .values()
            .map(|subscription| subscription.anchor.clone())
            .collect()
    }
}

pub(super) struct Confirmation {
    source: Subject,
    target: Vec<u8>,
    remove: bool,
    pub output: Bytes,
}
