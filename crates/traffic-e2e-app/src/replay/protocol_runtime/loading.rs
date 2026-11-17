//! Native Source interpretation enters the common startup pipeline through this port.
use super::*;
use crate::dependency_index::{FileIndex, RecordReader};
use traffic_protocol::connection::NativeFuture;

pub(crate) struct SourceResources {
    pub native: native::Inventory,
    pub targets: BTreeMap<TargetKey, ReplayTarget>,
    pub reader: Arc<std::sync::Mutex<RecordReader>>,
}

pub(crate) struct SourcePreparation {
    pub root: PathBuf,
    pub cases: BTreeMap<String, ReplayCase>,
    pub rules: Vec<crate::BackgroundDependencyRuleConfig>,
    pub lazy: bool,
}

/// The loader retains mutable native registration state until Source preparation
/// finishes. Its result carries the frozen session state used by live Replay.
pub(crate) trait ProtocolSourceLoader: Send + Sized + 'static {
    type Protocols: ReplayProtocolSet;
    type CaseSelector: Clone + Send + 'static;

    fn install_run_scopes(&mut self, scopes: BTreeMap<Uuid, Arc<str>>);
    fn load_run<'a>(
        &'a mut self,
        path: &'a Path,
        source: ReplaySource,
        rules: &'a [crate::BackgroundDependencyRuleConfig],
        resources: &'a mut SourceResources,
    ) -> NativeFuture<'a, ()>;
    fn freeze_global_layout(&mut self);
    fn prepare_run<'a>(
        &'a mut self,
        root: &'a Path,
        debug: Option<PathBuf>,
        resources: &'a mut SourceResources,
    ) -> NativeFuture<'a, ()>;

    fn case_selector(&self) -> Self::CaseSelector;
    fn startup_records(
        path: &Path,
        index: &FileIndex,
        reader: &mut RecordReader,
    ) -> Result<Vec<(usize, <Self::Protocols as ReplayProtocolSet>::SourceRecord)>>;
    fn shared_source_lines(
        path: &Path,
        index: &FileIndex,
        reader: &mut RecordReader,
        selector: &Self::CaseSelector,
    ) -> Result<BTreeSet<usize>>;
    fn register_source(
        &mut self,
        batch: dependencies::SourceBatch<'_, <Self::Protocols as ReplayProtocolSet>::SourceRecord>,
        resources: &mut SourceResources,
    ) -> Result<()>;
    fn load_case_metadata<'a>(
        &'a mut self,
        directory: &'a Path,
        resources: &'a mut SourceResources,
    ) -> NativeFuture<'a, ()>;
    fn prepare(
        self,
        context: SourcePreparation,
        resources: SourceResources,
    ) -> NativeFuture<'static, (Self, SourceResources)>;

    fn register_policy_sources(
        &self,
        policy: &mut <Self::Protocols as ReplayProtocolSet>::Policy,
    ) -> Result<()>;
    fn observe_policy_sources(
        &self,
        policy: &mut <Self::Protocols as ReplayProtocolSet>::Policy,
    ) -> Result<()>;
    fn finish(
        self,
        lazy: bool,
        observations: TargetObservations,
        policy: Option<&<Self::Protocols as ReplayProtocolSet>::Policy>,
    ) -> Self::Protocols;
}
