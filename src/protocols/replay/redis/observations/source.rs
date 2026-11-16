//! Bind complete native Source proofs to framework installation and clocks.
use super::*;
use traffic_protocol_redis::storage::observations as native;

pub(super) fn has_owned_set(
    state: &RedisReplayState,
    case: &str,
    seed: &ReplayExchange,
) -> Result<bool> {
    native::has_owned_set(&state.exchanges, case, seed)
}
pub(super) fn prepare(
    state: &RedisReplayState,
    case: &str,
    rule: &str,
    kind: Kind,
    seed: &ReplayExchange,
    transient_nil: bool,
) -> Result<Option<Profile>> {
    native::prepare(
        &state.exchanges,
        &state.connection_scopes,
        native::Configuration {
            case,
            rule,
            kind,
            transient_nil,
            prepared_at: chrono::Utc::now(),
        },
        seed,
    )
}
