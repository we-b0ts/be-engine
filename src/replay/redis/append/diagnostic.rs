//! Mismatch facts from an already validated Source stream, without payloads.
use super::*;
use crate::replay::report::command::CommandExchangeRefReport;

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct AppendMismatch {
    rule_id: String,
    target_observation: Option<Uuid>,
    source_key_fingerprint: String,
    payload_fingerprint: String,
    source_offset: usize,
    source_bytes_remaining: usize,
    target_bytes: usize,
    first_difference_offset: usize,
    next_source: Option<CommandExchangeRefReport>,
}

impl std::fmt::Display for AppendMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "append stream bytes differ from the next Source prefix at byte {}",
            self.first_difference_offset
        )
    }
}

impl std::error::Error for AppendMismatch {}

/// A validated Source observation/reset arrived at the wrong Target byte cursor.
#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct AppendBoundaryMismatch {
    rule_id: String,
    source_key_fingerprint: String,
    source_offset: usize,
    required_source_offset: usize,
    missing_bytes: usize,
    barrier: CommandExchangeRefReport,
}

impl std::fmt::Display for AppendBoundaryMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "append stream requires Source byte boundary {}, Target reached {}",
            self.required_source_offset, self.source_offset
        )
    }
}

impl std::error::Error for AppendBoundaryMismatch {}

pub(super) fn boundary_mismatch(
    profile: &Profile,
    exchange: &ReplayExchange,
    required_source_offset: usize,
) -> AppendBoundaryMismatch {
    AppendBoundaryMismatch {
        rule_id: profile.rule.clone(),
        source_key_fingerprint: crate::policy_evidence::digest(&profile.key),
        source_offset: profile.reserved,
        required_source_offset,
        missing_bytes: required_source_offset.saturating_sub(profile.reserved),
        barrier: CommandExchangeRefReport {
            case_id: exchange.case_id.clone(),
            source: exchange.source,
            connection_id: exchange.record.native.connection_id,
            sequence: exchange.record.native.sequence,
            command: exchange.record.native.command.clone(),
        },
    }
}

pub(super) fn bytes_mismatch(
    profile: &Profile,
    exchanges: &[ReplayExchange],
    actual: &[u8],
    target_observation: Option<Uuid>,
) -> AppendMismatch {
    let offset = profile.reserved;
    let remaining = profile.bytes.get(offset..).unwrap_or_default();
    let first_difference = remaining
        .iter()
        .zip(actual)
        .position(|(source, target)| source != target)
        .unwrap_or(remaining.len().min(actual.len()));
    let next_source = profile
        .pieces
        .iter()
        .find(|piece| offset < piece.end)
        .map(|piece| {
            let exchange = &exchanges[piece.index];
            CommandExchangeRefReport {
                case_id: exchange.case_id.clone(),
                source: exchange.source,
                connection_id: exchange.record.native.connection_id,
                sequence: exchange.record.native.sequence,
                command: exchange.record.native.command.clone(),
            }
        });
    AppendMismatch {
        rule_id: profile.rule.clone(),
        target_observation,
        source_key_fingerprint: crate::policy_evidence::digest(&profile.key),
        payload_fingerprint: crate::policy_evidence::digest(actual),
        source_offset: offset,
        source_bytes_remaining: profile.pieces.last().map_or(0, |piece| piece.end) - offset,
        target_bytes: actual.len(),
        first_difference_offset: offset + first_difference,
        next_source,
    }
}
