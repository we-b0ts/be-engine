//! Protocol control and proven reusable snapshots do not become startup business debt.
use super::*;
impl RedisReplayState {
    pub(crate) fn startup_counts(&mut self, close: bool) -> crate::replay::startup::Counts {
        let mut counts = crate::replay::startup::Counts::default();
        for (index, exchange) in self.exchanges.iter_mut().enumerate() {
            self.lifecycle.synchronize(index, &mut exchange.status);
            let control = matches!(
                exchange.record.native.command.as_str(),
                "PING"
                    | "QUIT"
                    | "AUTH"
                    | "HELLO"
                    | "SELECT"
                    | "CLIENT"
                    | "READONLY"
                    | "READWRITE"
                    | "SUBSCRIBE"
                    | "PSUBSCRIBE"
                    | "SSUBSCRIBE"
                    | "UNSUBSCRIBE"
                    | "PUNSUBSCRIBE"
                    | "SUNSUBSCRIBE"
            );
            counts.observe(
                exchange.source,
                &mut exchange.status,
                !control && !exchange.reusable_snapshot,
                close,
            );
        }
        counts.merge(self.pubsub.startup_counts(close));
        counts
    }
}
