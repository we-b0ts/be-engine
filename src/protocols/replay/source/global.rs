//! Bounded Global traversal projects all installed protocols through the same path.
use super::*;
use crate::dependency_index::global::{GlobalEntry, GlobalIndex};
use crate::dependency_index::{RecordReader, RecordRef, RecordSource};
use crate::replay::global::{GlobalProjection, GlobalRegistrar, Phase};
use std::sync::Arc;

pub(crate) struct Records;
impl GlobalProjection for Records {
    type Item = (DependencyRecord, RecordRef);
    fn validate(record: &Value) -> Result<()> {
        validate_index_record(record)
    }
    fn accepts(phase: Phase, record: &Value) -> Result<bool> {
        use anyhow::Context;
        let kind = record["event_type"]
            .as_str()
            .context("Global record lacks event_type")?;
        let metadata = kind == "proxy_error" || kind.ends_with("_connection");
        Ok(match phase {
            Phase::Metadata => metadata,
            Phase::Exchanges => !metadata,
        })
    }
    fn decode(entry: GlobalEntry, source: &Arc<RecordSource>) -> Result<Self::Item> {
        use traffic_protocol::evidence::RecordSource as _;
        let reference = source.reference(entry.location);
        let record = serde_json::from_value(entry.record)?;
        let record = match record {
            DependencyRecord::Native(_) => reference.load()?,
            record => record,
        };
        Ok((record, reference))
    }
}
struct Registration<'a> {
    path: &'a Path,
    source_kind: ReplaySource,
    targets: &'a mut BTreeMap<TargetKey, ReplayTarget>,
    native: &'a mut native::Inventory,
}
impl GlobalRegistrar for Registration<'_> {
    type Projection = Records;
    fn prepare(&mut self, index: &GlobalIndex, _: &Path, _: Arc<RecordSource>) -> Result<()> {
        ensure!(
            index.notifications.is_empty(),
            "recorded notifications require a native notification capability"
        );
        Ok(())
    }
    fn register(&mut self, _: Phase, item: <Records as GlobalProjection>::Item) -> Result<()> {
        let (record, reference) = item;
        register_dependency_records(
            self.path,
            vec![(reference.location.line, record)],
            &BTreeSet::new(),
            self.source_kind,
            None,
            self.targets,
            &[],
            &BTreeSet::new(),
            self.native,
        )
    }
    fn complete(&mut self, _: Phase) -> Result<()> {
        Ok(())
    }
}
pub(crate) async fn load(
    path: &Path,
    source_kind: ReplaySource,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    _rules: &[crate::BackgroundDependencyRuleConfig],
    reader: Arc<std::sync::Mutex<RecordReader>>,
    native: &mut native::Inventory,
) -> Result<()> {
    if source_kind == ReplaySource::Unattributed {
        use anyhow::Context;
        let path = path.to_owned();
        let (index, _) = tokio::task::spawn_blocking(move || {
            crate::dependency_index::global::load_global_index(&path, validate_index_record)
        })
        .await
        .context("ambient Source preparation failed")??;
        ensure!(
            index.notifications.is_empty(),
            "recorded notifications require a native notification capability"
        );
        return Ok(());
    }
    replay::global::load(
        path,
        reader,
        &mut Registration {
            path,
            source_kind,
            targets,
            native,
        },
    )
    .await
}
