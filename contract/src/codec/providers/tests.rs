use super::*;
use std::sync::Arc;
use traffic_value::{Value as Logical, codec::ValueDocument};

struct Document {
    original: Logical,
    projection: Logical,
}
impl ValueDocument for Document {
    fn value(&self) -> &Logical {
        &self.original
    }
    fn original_bytes(&self) -> &[u8] {
        b"fixture"
    }
    fn comparison_view<'a>(&'a self, _: &[String]) -> Cow<'a, Logical> {
        Cow::Borrowed(&self.projection)
    }
    fn encode(&self, _: &Logical, _: &[String]) -> Result<Vec<u8>> {
        anyhow::bail!("fixture document is read-only")
    }
}

#[test]
fn a_codec_can_borrow_a_comparison_projection_distinct_from_its_full_value() {
    let original = Logical::String("complete native value".into());
    let projection = Logical::String("codec-owned comparison view".into());
    let document = DecodedDocument {
        logical: serde_json::to_value(&original).unwrap(),
        document: Arc::new(Document {
            original,
            projection: projection.clone(),
        }),
        kind: CodecKind(Cow::Borrowed("fixture")),
    };
    assert_eq!(
        document.comparison_view(&[]).as_ref(),
        &serde_json::to_value(&projection).unwrap()
    );
    assert_eq!(document.logical_comparison_view(&[]).as_ref(), &projection);
}
