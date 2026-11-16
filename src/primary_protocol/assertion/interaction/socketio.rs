//! Application policy integration for native Socket.IO comparison.
use super::*;
fn compare_message(
    source: &WireMessage,
    target: &WireMessage,
    global: &crate::policy::CompiledJsonPolicy,
    clocks: crate::value_contract::json::AnchorClocks,
    pointer: &str,
    max_message_bytes: usize,
) -> Result<Option<Comparison>> {
    verification::socketio::compare_message(
        source,
        target,
        &ValueAdapter {
            plan: global,
            copies: &Default::default(),
        },
        clocks,
        pointer,
        max_message_bytes,
    )
}
mod tests;
