//! Load an immutable native response only after its Source output is admitted.
use super::*;
use crate::dependency_index::RecordRef;
use bytes::Bytes;
use traffic_protocol::message::{MessageEncoder, ProjectedMessage, ProtocolMessage, StoredMessage};

pub(super) struct Response {
    pub reference: RecordRef,
    pub providers: Arc<crate::protocols::DependencyProviders>,
    pub protocol: crate::protocols::DependencyProtocol,
    pub structure: Option<Value>,
}

impl StoredMessage for Response {
    fn load(&self) -> Result<Arc<dyn MessageEncoder>> {
        let event: Value = self.reference.load()?;
        let provider = self.providers.provider(self.protocol)?;
        let native = provider
            .native_protocol()
            .context("stored response has no native protocol")?;
        let secrets = crate::request_headers::SourceSecrets::new(self.reference.source.path());
        Ok(native
            .recorded_exchange_with_secrets(&event, &secrets)?
            .context("stored response has no executable exchange")?
            .response)
    }

    fn source_structure(&self) -> Option<&Value> {
        self.structure.as_ref()
    }
}

impl ProtocolMessage for Response {
    fn project(&self) -> Result<ProjectedMessage> {
        self.load()?.project()
    }
    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        self.load()?.locate(selector)
    }
    fn evidence(&self, selector: &Value) -> Result<Value> {
        self.load()?.evidence(selector)
    }
}

impl MessageEncoder for Response {
    fn stored(&self) -> Option<&dyn StoredMessage> {
        Some(self)
    }
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        self.load()?.encode(values)
    }
}
