//! Select the complete native-reference set used by one API's unused inventory.
use super::*;

#[derive(PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
enum Reference {
    Exchange(Uuid),
    Http(String),
    Native(String, String, u64),
}

pub(super) struct Selection {
    pub identity: String,
    pub apis: BTreeMap<Uuid, String>,
    references: BTreeSet<Reference>,
    has_native: bool,
}

impl Selection {
    pub fn is_empty(&self) -> bool {
        self.references.is_empty()
    }
    pub fn new(api: &str, report: &Value, mut apis: BTreeMap<Uuid, String>) -> Result<Self> {
        apis.retain(|_, method| method == api);
        let cases = apis.keys().map(Uuid::to_string).collect();
        let references = collect_unused(report, &cases, |protocol, event| {
            if let Some(id) = event["source_exchange_id"]
                .as_str()
                .or_else(|| event["capture"]["exchange_id"].as_str())
            {
                return Ok(Reference::Exchange(id.parse()?));
            }
            ensure!(
                event["command"] != "PUBSUB_PUSH",
                "unused Pub/Sub notification lacks its own Source exchange identity; run a fresh Replay to publish notification identities"
            );
            Ok(if protocol == "http" {
                Reference::Http(
                    event["source_http_id"]
                        .as_str()
                        .context("unused HTTP entry lacks exact Source HTTP identity")?
                        .into(),
                )
            } else {
                Reference::Native(
                    protocol.into(),
                    event["connection_id"]
                        .as_str()
                        .context("unused dependency lacks native connection identity")?
                        .into(),
                    event["query_sequence"]
                        .as_u64()
                        .or_else(|| event["sequence"].as_u64())
                        .context("unused dependency lacks native sequence")?,
                )
            })
        })?;
        Ok(Self {
            identity: digest(&serde_json::to_vec(&(api, &apis, &references))?),
            has_native: references
                .iter()
                .any(|reference| !matches!(reference, Reference::Exchange(_))),
            apis,
            references,
        })
    }

    pub fn matches(&self, capture: &CaptureMetadata, event: &Value) -> Result<bool> {
        if self
            .references
            .contains(&Reference::Exchange(capture.exchange_id))
        {
            return Ok(true);
        }
        if !self.has_native {
            return Ok(false);
        }
        let reference = serde_json::to_value(&capture.protocol_ref)?;
        if let (Some(protocol), Some(connection), Some(sequence)) = (
            reference["protocol"].as_str(),
            reference["connection_id"].as_str(),
            reference["sequence"].as_u64(),
        ) && self.references.contains(&Reference::Native(
            protocol.into(),
            connection.into(),
            sequence,
        )) {
            return Ok(true);
        }
        Ok(reference["exchange_id"]
            .as_str()
            .or_else(|| event["id"].as_str())
            .is_some_and(|id| self.references.contains(&Reference::Http(id.into()))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::observation::{ProtocolRef, fixture_capture};

    #[test]
    fn native_selection_keeps_all_ambiguous_originals_and_notification_ids_stay_required() {
        let case = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let event = json!({"case_id":case,"connection_id":connection,"query_sequence":1});
        let report = json!({"unused_case_exchanges":[event.clone()]});
        let apis = BTreeMap::from([(case, "GET /api".into())]);
        let selected = Selection::new("GET /api", &report, apis.clone()).unwrap();
        let mut native = BTreeMap::new();
        let mut http = BTreeMap::new();
        for _ in 0..2 {
            let mut capture = fixture_capture("case");
            capture.protocol_ref = ProtocolRef::connection("mysql", connection, 1);
            assert!(selected.matches(&capture, &json!({})).unwrap());
            observe_reference(&mut native, &mut http, &capture, &json!({})).unwrap();
        }
        assert!(
            resolve_unused_reference(&BTreeMap::new(), &native, &http, "mysql", &event)
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
        assert!(
            Selection::new(
                "GET /api",
                &json!({"redis":{"unused_case":[{
            "case_id":case,"command":"PUBSUB_PUSH","connection_id":connection,"sequence":1}]}}),
                apis
            )
            .is_err()
        );
    }
}
