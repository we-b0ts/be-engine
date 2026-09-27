use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::dependency::termination::ConnectionTermination;
use crate::redis::{
    RedisCommand, RedisPubSubPush, RedisSubscriptionKind, validate_subscription_confirmation,
};

#[derive(Debug, Clone, Default)]
pub(super) struct Subscriptions {
    channels: BTreeSet<Vec<u8>>,
    patterns: BTreeSet<Vec<u8>>,
    shard_channels: BTreeSet<Vec<u8>>,
}

impl Subscriptions {
    pub(super) fn is_active(&self) -> bool {
        !self.channels.is_empty() || !self.patterns.is_empty() || !self.shard_channels.is_empty()
    }

    pub(super) fn accepts(&self, push: &RedisPubSubPush) -> bool {
        match push.subscription_kind {
            RedisSubscriptionKind::Channel => self.channels.contains(&push.subject),
            RedisSubscriptionKind::Pattern => self.patterns.contains(&push.subject),
            RedisSubscriptionKind::ShardChannel => self.shard_channels.contains(&push.subject),
        }
    }

    pub(super) fn record_confirmation(&mut self, command: &RedisCommand, response: &[u8]) {
        if validate_subscription_confirmation(command, response).is_err() {
            return;
        }
        let Some(subject) = command.args.first().cloned() else {
            return;
        };
        match command.name.as_str() {
            "SUBSCRIBE" => {
                self.channels.insert(subject);
            }
            "PSUBSCRIBE" => {
                self.patterns.insert(subject);
            }
            "SSUBSCRIBE" => {
                self.shard_channels.insert(subject);
            }
            _ => {}
        }
    }
}

pub(super) async fn write_push(
    client_write: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    termination: &ConnectionTermination,
    client_open: &mut bool,
    bytes: &mut u64,
    payload: &[u8],
) -> Result<()> {
    if !*client_open || termination.client_ended_first() {
        *client_open = false;
        return Ok(());
    }
    match client_write.lock().await.write_all(payload).await {
        Ok(()) => *bytes += payload.len() as u64,
        Err(error) if termination.observe_client_io_error(&error) => *client_open = false,
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redis::parse_pubsub_push;

    #[test]
    fn accepts_only_pushes_for_the_confirmed_subscription() {
        let command = RedisCommand {
            name: "SUBSCRIBE".to_string(),
            args: vec![b"events".to_vec()],
        };
        let mut subscriptions = Subscriptions::default();
        subscriptions
            .record_confirmation(&command, b"*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n");

        let matching =
            parse_pubsub_push(b"*3\r\n$7\r\nmessage\r\n$6\r\nevents\r\n$7\r\npayload\r\n")
                .unwrap()
                .unwrap();
        let other = parse_pubsub_push(b"*3\r\n$7\r\nmessage\r\n$5\r\nother\r\n$7\r\npayload\r\n")
            .unwrap()
            .unwrap();

        assert!(subscriptions.accepts(&matching));
        assert!(!subscriptions.accepts(&other));
    }
}
