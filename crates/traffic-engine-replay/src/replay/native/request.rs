//! Native requests enter the common observe/select/wait/commit execution loop.
use super::*;
use traffic_contract::{compare::Comparison, identity::IdentityDecision};
use traffic_protocol::message::ProtocolMessage;

pub struct Request {
    pub protocol: ProtocolId,
    pub endpoint: Endpoint,
    pub message: Arc<dyn ProtocolMessage>,
    pub session: Option<Uuid>,
    pub lane: Option<String>,
    pub observed: DateTime<Utc>,
    pub bytes: usize,
    pub diagnostics: diagnosis::CandidateDiagnostics,
}

pub struct Matched {
    pub index: usize,
    pub ticket: admission::ClaimTicket,
    pub observed: DateTime<Utc>,
    pub delay: std::time::Duration,
    pub case: Option<String>,
    pub epoch: u64,
    pub run_owned: bool,
}

pub struct Rejected {
    pub reason: String,
    pub blocker: Option<usize>,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}
impl std::fmt::Debug for Rejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}
impl std::error::Error for Rejected {}
impl From<anyhow::Error> for Rejected {
    fn from(error: anyhow::Error) -> Self {
        Self {
            reason: error.to_string(),
            blocker: None,
        }
    }
}

pub fn identity(
    owner: &dyn policy::ValueRuleHost,
    inventory: &Inventory,
    index: usize,
    comparison: &Comparison,
) -> Result<IdentityDecision> {
    let scope = inventory.scope(index);
    owner.preview_identity_pairs(
        &scope,
        &comparison.identity_pairs(),
        inventory.core.exchanges[index].source.source == ReplaySource::Case,
    )
}

pub struct ResponsePlan {
    pub output: Box<dyn traffic_protocol::output::OutputStream>,
    pub comparison: Comparison,
    pub identity: IdentityDecision,
}

impl Inventory {
    pub fn render_response(
        &self,
        index: usize,
        observed: DateTime<Utc>,
        loaded: Option<&dyn traffic_protocol::message::MessageEncoder>,
    ) -> Result<ResponsePlan> {
        let exchange = &self.core.exchanges[index];
        let prepared;
        let (response, encoder) = if let Some(encoder) = loaded {
            prepared = self
                .prepared_messages(
                    &exchange.native,
                    exchange.source.case_id.as_deref(),
                    exchange.source.capture.as_ref(),
                    self.contracts.as_ref(),
                    Some(encoder),
                )?
                .1
                .context("stored response was not prepared")?;
            (&prepared, encoder)
        } else {
            (
                exchange
                    .response
                    .as_ref()
                    .context("response was not prepared")?,
                exchange.native.response.as_ref(),
            )
        };
        let scope = self.scope(index);
        let clocks = self.clocks(index, observed, true);
        let rendered = response.render_delivery_with_documents(
            clocks,
            self.contracts.metadata(),
            &exchange.delivery,
            |selected| {
                self.contracts
                    .identity_deliveries(&scope, selected)
                    .map(|(values, _)| values)
            },
            |source, delivered| {
                self.contracts
                    .translate_document(&scope, source, delivered, clocks)
            },
        )?;
        let proposed = identity(self.contracts.as_ref(), self, index, &rendered.comparison)?;
        let response = encoder.output(&rendered.values)?;
        Ok(ResponsePlan {
            output: response,
            comparison: rendered.comparison,
            identity: proposed,
        })
    }
}
