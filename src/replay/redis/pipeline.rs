//! A blocked adapter publish may read exactly one pipelined RESP request.
use super::*;
use crate::dependency::termination::ConnectionControl;
use crate::redis::RedisFrame;
use tokio::{pin, sync::mpsc, time::Instant};

type QueuedFrame = (Result<Option<RedisFrame>>, Instant);

pub(super) struct Request<'a> {
    pub(super) state: &'a Arc<Mutex<ReplayState>>,
    pub(super) target: &'a TargetKey,
    pub(super) client_id: Uuid,
    pub(super) resp_version: u8,
    pub(super) database: i64,
    pub(super) username: Option<&'a str>,
    pub(super) command: &'a RedisCommand,
    pub(super) started: Instant,
}

impl Request<'_> {
    pub(super) async fn serve(
        &self,
        reader: &mut RedisBufferedReader<&mut TcpStream>,
        control: &ConnectionControl,
        binding: &mut CaseConnectionBinding,
        push_tx: &mpsc::Sender<pubsub::Delivery>,
        queued: &mut Option<QueuedFrame>,
    ) -> Result<bool> {
        let (response, predecessor) = if self.command.name == "PUBLISH" {
            self.admit_with_lookahead(reader, binding, queued).await
        } else {
            (self.admit(binding, None).await, None)
        };
        let Ok(matched) = response else {
            return Ok(true);
        };
        if let Err(error) =
            crate::replay::policy::request_contract::hypotheses::await_durable(self.state).await
        {
            let mut state = self.state.lock().await;
            let reason = "hypothesis evidence persistence failed";
            state.redis.fail_exchange(&matched, reason.into());
            if let Some((earlier, _)) = predecessor {
                state.redis.fail_exchange(&earlier, reason.into());
            }
            return Err(error);
        }
        if let Some((earlier, started)) = predecessor {
            delivery::deliver_publish_pair(
                reader,
                self.state,
                (&earlier, started),
                (&matched, self.started),
            )
            .await?;
            tracing::info!(
                source_connection = %matched.connection_id,
                source_earlier = earlier.report.sequence,
                source_later = matched.report.sequence,
                target_first = ?matched.report.target_event_index,
                target_second = ?earlier.report.target_event_index,
                "completed adjacent Socket.IO publishes with FIFO Redis replies"
            );
            return Ok(false);
        }
        let deliveries = self.state.lock().await.redis.pubsub.subscription(
            self.client_id,
            self.target,
            self.database,
            self.username,
            self.command,
            &matched,
            push_tx.clone(),
        )?;
        if deliver_redis_exchange(
            reader,
            self.state,
            &matched,
            control,
            self.started,
            self.client_id,
        )
        .await?
        {
            return Ok(true);
        }
        if let Some(deliveries) = deliveries {
            pubsub::schedule_notifications(self.state.clone(), deliveries);
        }
        Ok(false)
    }

    async fn admit(
        &self,
        binding: &mut CaseConnectionBinding,
        hint: Option<&mpsc::Sender<admission::pipeline::AdjacentPublish>>,
    ) -> std::result::Result<MatchedRedisExchange, &'static str> {
        admission::match_command_with_hint(
            self.state,
            self.target,
            self.client_id,
            binding,
            self.resp_version,
            self.database,
            self.username,
            self.command,
            hint,
        )
        .await
    }

    async fn admit_with_lookahead(
        &self,
        reader: &mut RedisBufferedReader<&mut TcpStream>,
        binding: &mut CaseConnectionBinding,
        queued: &mut Option<QueuedFrame>,
    ) -> (
        std::result::Result<MatchedRedisExchange, &'static str>,
        Option<(MatchedRedisExchange, Instant)>,
    ) {
        let original_binding = binding.clone();
        let (hints, mut blocked) = mpsc::channel(1);
        let first = self.admit(binding, Some(&hints));
        pin!(first);
        let Some(pair) = (tokio::select! {
            biased;
            response = &mut first => return (response, None),
            pair = blocked.recv() => pair,
        }) else {
            return (first.await, None);
        };
        blocked.close();
        let read = tokio::select! {
            biased;
            response = &mut first => return (response, None),
            read = read_redis_frame(reader) => read,
        };
        let started = Instant::now();
        if let Ok(Some(frame)) = &read
            && let Ok(command) = redis_command(&frame.raw)
            && let Some(predecessor) = pair
                .admit_predecessor(
                    self.state,
                    self.target,
                    self.client_id,
                    original_binding,
                    self.resp_version,
                    self.database,
                    self.username,
                    &command,
                )
                .await
        {
            let Ok(predecessor) = predecessor else {
                return (Err("pipelined Redis predecessor was rejected"), None);
            };
            let response = first.await;
            if !matches!(&response, Ok(matched) if matched.index == pair.later()) {
                let mut state = self.state.lock().await;
                let reason = "pipelined Redis successor changed";
                state.redis.fail_exchange(&predecessor, reason.into());
                if let Ok(matched) = response {
                    state.redis.fail_exchange(&matched, reason.into());
                }
                return (Err(reason), None);
            }
            return (response, Some((predecessor, started)));
        }
        *queued = Some((read, started));
        (first.await, None)
    }
}
