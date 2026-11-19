//! Bounded Global traversal projects all installed protocols through the same path.
use super::*;
use crate::dependency_index::global::{GlobalEntry, GlobalIndex};
use crate::dependency_index::{RecordReader, RecordRef, RecordSource};
use crate::replay::global::{GlobalProjection, GlobalRegistrar, Phase};
use std::sync::Arc;

pub struct Records;
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
    fn evidence(&self) -> Option<traffic_protocol::evidence::EvidenceRegistry> {
        Some(self.native.providers.evidence().clone())
    }
    fn prepare(
        &mut self,
        index: &GlobalIndex,
        root: &Path,
        source: Arc<RecordSource>,
    ) -> Result<()> {
        for lane in &index.notifications {
            let pages = crate::dependency_index::Paged::<
                crate::dependency_index::global::NotificationEntry,
            >::restore(lane.pages.clone().resolve(root)?)?;
            for page in 0..pages.pages() {
                for entry in pages.read_page(page)? {
                    let reference = source.reference(entry.location);
                    let record = reference.load()?;
                    self.register(Phase::Exchanges, (record, reference))?;
                }
            }
        }
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
pub async fn load(
    path: &Path,
    source_kind: ReplaySource,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    _rules: &[crate::BackgroundDependencyRuleConfig],
    reader: Arc<std::sync::Mutex<RecordReader>>,
    native: &mut native::Inventory,
) -> Result<()> {
    let resolved = crate::dependency_index::scoped::resolve(path)?;
    if resolved
        .path
        .file_name()
        .is_some_and(|name| name == "dependency-locations.bin")
    {
        let path = path.to_owned();
        let providers = native.providers.clone();
        let mut inventory = std::mem::replace(native, native::Inventory::new(providers));
        let mut destinations = std::mem::take(targets);
        (*native, *targets) = tokio::task::spawn_blocking(move || {
            direct(
                &path,
                resolved,
                source_kind,
                reader,
                &mut inventory,
                &mut destinations,
            )?;
            Ok::<_, anyhow::Error>((inventory, destinations))
        })
        .await??;
        return Ok(());
    }
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

fn direct(
    path: &Path,
    resolved: crate::dependency_index::scoped::Source,
    scope: ReplaySource,
    reader: Arc<std::sync::Mutex<RecordReader>>,
    native: &mut native::Inventory,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
) -> Result<()> {
    use anyhow::Context;
    if scope == ReplaySource::Unattributed {
        return Ok(());
    }
    let locations = resolved
        .locations
        .context("compact Global stream has no scope")?;
    let stamp = crate::dependency_index::FileStamp::read_native(&resolved.path)?;
    let source = RecordSource::new(&resolved.path, stamp, reader);
    let secrets = crate::request_headers::SourceSecrets::new(path);
    for location in locations.iter() {
        let reference = source.reference(location.clone());
        let metadata = reference.load_metadata()?;
        if native.register_stored_emission(
            &metadata,
            scope,
            targets,
            reference.clone(),
            &secrets,
        )? {
            continue;
        }
        let record: DependencyRecord = reference.load()?;
        register_dependency_records(
            path,
            vec![(location.line, record)],
            &BTreeSet::new(),
            scope,
            None,
            targets,
            &[],
            &BTreeSet::new(),
            native,
        )?;
    }
    Ok(())
}
