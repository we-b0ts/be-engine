use super::*;
use serde_json::json;
use std::borrow::Cow;

struct Custom;

impl EvidenceAdapter for Custom {
    fn schema(&self) -> &'static str {
        "custom/v1"
    }

    fn event_types(&self) -> &'static [&'static str] {
        &["custom_exchange"]
    }

    fn supports_replay(&self, _: &Value) -> bool {
        true
    }

    fn source_payload(
        &self,
        protocol: &str,
        event: &Value,
        side: MessageSide,
        secrets: &dyn EvidenceSecrets,
    ) -> Result<Option<Vec<u8>>> {
        if protocol != "custom" {
            return Ok(None);
        }
        let field = match side {
            MessageSide::Request => "input",
            MessageSide::Response => "output",
        };
        let value = event[field].as_str().context("missing custom value")?;
        Ok(Some(secrets.unseal_text(field, value)?.as_bytes().to_vec()))
    }
}

struct Secrets;

impl EvidenceSecrets for Secrets {
    fn unseal_text<'a>(&self, label: &str, value: &'a str) -> Result<Cow<'a, str>> {
        Ok(Cow::Owned(format!("{label}={value}")))
    }
}

#[test]
fn registered_native_owner_projects_both_sides_using_host_secrets() {
    let mut registry = EvidenceRegistry::default();
    registry.register("custom", Arc::new(Custom)).unwrap();
    let event = json!({"event_type":"custom_exchange", "input":"request", "output":"response"});
    for (side, expected) in [
        (MessageSide::Request, "input=request"),
        (MessageSide::Response, "output=response"),
    ] {
        assert_eq!(
            registry
                .source_payload("custom", &event, side, &Secrets)
                .unwrap(),
            Some(expected.as_bytes().to_vec())
        );
        assert!(
            registry
                .source_payload("other", &event, side, &Secrets)
                .unwrap()
                .is_none()
        );
    }
    assert!(
        registry
            .source_payload(
                "custom",
                &json!({"event_type":"unknown"}),
                MessageSide::Request,
                &Secrets
            )
            .unwrap()
            .is_none()
    );
}
