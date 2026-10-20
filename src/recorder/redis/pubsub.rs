mod capture;
mod evidence;
pub(super) use capture::{CapturedPush, capture};
pub(super) use evidence::record_subscription;
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
    anchors: std::collections::HashMap<(RedisSubscriptionKind, Vec<u8>), (u64, std::time::Instant)>,
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

    pub(super) fn set_anchor(&mut self, command: &RedisCommand, sequence: u64) {
        let Some(subject) = command.args.first() else {
            return;
        };
        let kind = match command.name.as_str() {
            "SUBSCRIBE" | "UNSUBSCRIBE" => RedisSubscriptionKind::Channel,
            "PSUBSCRIBE" | "PUNSUBSCRIBE" => RedisSubscriptionKind::Pattern,
            "SSUBSCRIBE" | "SUNSUBSCRIBE" => RedisSubscriptionKind::ShardChannel,
            _ => return,
        };
        let key = (kind, subject.clone());
        if command.name.starts_with('U') || command.name.contains("UNSUBSCRIBE") {
            self.anchors.remove(&key);
        } else {
            self.anchors
                .insert(key, (sequence, std::time::Instant::now()));
        }
    }

    pub(super) fn anchor(&self, push: &RedisPubSubPush) -> Option<(u64, u64)> {
        self.anchors
            .get(&(push.subscription_kind, push.subject.clone()))
            .map(|(sequence, time)| (*sequence, time.elapsed().as_millis() as u64))
    }

    pub(super) fn record_confirmation(&mut self, command: &RedisCommand, response: &[u8]) -> bool {
        if validate_subscription_confirmation(command, response).is_err() {
            return false;
        }
        let Some(subject) = command.args.first().cloned() else {
            return false;
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
            "UNSUBSCRIBE" => {
                self.channels.remove(&subject);
            }
            "PUNSUBSCRIBE" => {
                self.patterns.remove(&subject);
            }
            "SUNSUBSCRIBE" => {
                self.shard_channels.remove(&subject);
            }
            _ => return false,
        }
        true
    }
}

pub(super) async fn write_push(
    client_write: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    termination: &ConnectionTermination,
    client_open: &mut bool,
    bytes: &mut u64,
    payload: &[u8],
) -> Result<bool> {
    if !*client_open {
        *client_open = false;
        return Ok(false);
    }
    match client_write.lock().await.write_all(payload).await {
        Ok(()) => {
            *bytes += payload.len() as u64;
            return Ok(true);
        }
        Err(error) if termination.observe_client_io_error(&error) => *client_open = false,
        Err(error) => return Err(error.into()),
    }
    Ok(false)
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

    #[test]
    fn unsubscription_removes_only_the_confirmed_subject_and_kind() {
        for (subscribe, unsubscribe, kind) in [
            ("SUBSCRIBE", "UNSUBSCRIBE", RedisSubscriptionKind::Channel),
            ("PSUBSCRIBE", "PUNSUBSCRIBE", RedisSubscriptionKind::Pattern),
            (
                "SSUBSCRIBE",
                "SUNSUBSCRIBE",
                RedisSubscriptionKind::ShardChannel,
            ),
        ] {
            let mut subscriptions = Subscriptions::default();
            for (subject, count) in [("events", 1), ("other", 2)] {
                let command = RedisCommand {
                    name: subscribe.to_string(),
                    args: vec![subject.as_bytes().to_vec()],
                };
                let response = confirmation(subscribe, subject, count);
                subscriptions.record_confirmation(&command, response.as_bytes());
            }
            let command = RedisCommand {
                name: unsubscribe.to_string(),
                args: vec![b"events".to_vec()],
            };
            // A Redis error or malformed confirmation cannot change active subjects.
            for response in [
                "-ERR denied\r\n".to_string(),
                confirmation(unsubscribe, "other", 1),
                confirmation(unsubscribe, "events", -1),
            ] {
                subscriptions.record_confirmation(&command, response.as_bytes());
                assert!(subscriptions.accepts(&RedisPubSubPush {
                    subscription_kind: kind,
                    channel: Vec::new(),
                    payload: Vec::new(),
                    subject: b"events".to_vec(),
                }));
            }
            subscriptions
                .record_confirmation(&command, confirmation(unsubscribe, "events", 1).as_bytes());
            assert!(!subscriptions.accepts(&RedisPubSubPush {
                subscription_kind: kind,
                channel: Vec::new(),
                payload: Vec::new(),
                subject: b"events".to_vec(),
            }));
            assert!(subscriptions.accepts(&RedisPubSubPush {
                subscription_kind: kind,
                channel: Vec::new(),
                payload: Vec::new(),
                subject: b"other".to_vec(),
            }));
            assert!(subscriptions.is_active());

            let command = RedisCommand {
                name: unsubscribe.to_string(),
                args: vec![b"other".to_vec()],
            };
            subscriptions
                .record_confirmation(&command, confirmation(unsubscribe, "other", 0).as_bytes());
            assert!(!subscriptions.is_active());
        }
    }

    #[test]
    fn channel_unsubscription_does_not_remove_the_same_pattern_or_shard_channel() {
        let mut subscriptions = Subscriptions::default();
        for (name, count) in [("SUBSCRIBE", 1), ("PSUBSCRIBE", 2), ("SSUBSCRIBE", 1)] {
            let command = RedisCommand {
                name: name.to_string(),
                args: vec![b"events".to_vec()],
            };
            subscriptions
                .record_confirmation(&command, confirmation(name, "events", count).as_bytes());
        }
        let command = RedisCommand {
            name: "UNSUBSCRIBE".to_string(),
            args: vec![b"events".to_vec()],
        };
        subscriptions.record_confirmation(
            &command,
            confirmation("UNSUBSCRIBE", "events", 1).as_bytes(),
        );
        for kind in [
            RedisSubscriptionKind::Pattern,
            RedisSubscriptionKind::ShardChannel,
        ] {
            assert!(subscriptions.accepts(&RedisPubSubPush {
                subscription_kind: kind,
                channel: Vec::new(),
                payload: Vec::new(),
                subject: b"events".to_vec(),
            }));
        }
    }

    fn confirmation(name: &str, subject: &str, count: i64) -> String {
        format!(
            "*3\r\n${}\r\n{}\r\n${}\r\n{subject}\r\n:{count}\r\n",
            name.len(),
            name.to_ascii_lowercase(),
            subject.len()
        )
    }
}
