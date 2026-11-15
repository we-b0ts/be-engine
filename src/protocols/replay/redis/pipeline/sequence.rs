//! Keep reading this RESP connection while its next output awaits later inputs.
use super::*;

pub(super) type Admitted = (
    RedisCommand,
    std::result::Result<MatchedRedisExchange, &'static str>,
    CaseConnectionBinding,
    Instant,
);

#[derive(Default)]
pub(in crate::protocols::replay::redis) struct Queue {
    pub(in crate::protocols::replay::redis) frame: Option<QueuedFrame>,
    pub(in crate::protocols::replay::redis) admissions: traffic_replay::AdmissionQueue<Admitted>,
}

impl Request<'_> {
    pub(in crate::protocols::replay::redis) async fn await_sequence(
        &self,
        reader: &mut RedisBufferedReader<&mut TcpStream>,
        binding: &CaseConnectionBinding,
        queued: &mut Queue,
        matched: &MatchedRedisExchange,
    ) -> Result<()> {
        let Claim::Finite(ticket) = &matched.claim else {
            return Ok(());
        };
        let Some(sequence) = ticket.sequence() else {
            return Ok(());
        };
        if matched.timing.outcome() != DependencyExchangeOutcome::Response {
            return ticket.wait_sequence_delivery().await;
        }
        let output = ticket.wait_sequence_delivery();
        pin!(output);
        loop {
            // A session-changing command stays in the connection dispatcher.
            // It must be applied before admitting any subsequent command.
            if queued.frame.is_some() {
                return output.await;
            }
            let read = tokio::select! {
                biased;
                result = &mut output => return result,
                read = read_redis_frame(reader) => read,
            };
            let started = Instant::now();
            let command = read
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .and_then(|frame| redis_command(&frame.raw).ok())
                .filter(|command| {
                    !redis_is_builtin(&command.name) && !redis_is_unsupported(command)
                });
            let Some(command) = command else {
                queued.frame = Some((read, started));
                return output.await;
            };
            let bytes = read
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .map_or(0, |frame| frame.raw.len());
            let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
            let state = self.state.clone();
            let target = self.target.clone();
            let client_id = self.client_id;
            let mut binding = binding.clone();
            let resp_version = self.resp_version;
            let database = self.database;
            let username = self.username.map(str::to_owned);
            queued.admissions.push(sequence, bytes, async move {
                let matched = admission::match_command_with_hint(
                    &state,
                    &target,
                    client_id,
                    &mut binding,
                    resp_version,
                    database,
                    username.as_deref(),
                    &command,
                    None,
                    Some(observed_tx),
                )
                .await;
                (command, matched, binding, started)
            })?;
            // Preserve actual Target arrival order even when several complete
            // frames were already buffered before their tasks were scheduled.
            let _ = observed_rx.await;
        }
    }
}
