//! Native Global preparation and record projection supplied to bounded traversal.
use super::*;
use crate::dependency_index::global::{GlobalEntry, GlobalIndex};
use crate::dependency_index::{RecordReader, RecordRef, RecordSource};
use crate::replay::global::{GlobalProjection, GlobalRegistrar, Phase};
use std::sync::Arc;

pub(crate) struct Records;
impl GlobalProjection for Records {
    type Item = (DependencyRecord, RecordRef, Option<(usize, bool)>);
    fn validate(record: &Value) -> Result<()> {
        validate_index_record(record)
    }
    fn accepts(phase: Phase, record: &Value) -> Result<bool> {
        let kind = record["event_type"]
            .as_str()
            .context("Global index record lacks an event type")?;
        let metadata = matches!(kind, "mysql_connection" | "mysql_exchange" | "proxy_error");
        Ok(match phase {
            Phase::Metadata => metadata,
            Phase::Exchanges => !metadata,
        })
    }
    fn decode(entry: GlobalEntry, source: &Arc<RecordSource>) -> Result<Self::Item> {
        let reference = source.reference(entry.location);
        let record = serde_json::from_value(entry.record)?;
        // Compact indexes omit native payloads. Projection requires the authenticated original.
        let record = match record {
            DependencyRecord::Native(_) => reference.load()?,
            record => record,
        };
        Ok((record, reference, entry.mysql_row_shape))
    }
}

struct Registration<'a> {
    path: &'a Path,
    source_kind: ReplaySource,
    mysql: &'a mut MysqlReplayState,

    targets: &'a mut BTreeMap<TargetKey, ReplayTarget>,
    identities: &'a mut HashMap<Uuid, MysqlDependencyIdentity>,
    rules: &'a [crate::BackgroundDependencyRuleConfig],
    native: &'a mut native::Inventory,
    sql: Vec<(usize, DependencyRecord)>,
}

impl GlobalRegistrar for Registration<'_> {
    type Projection = Records;
    fn prepare(
        &mut self,
        index: &GlobalIndex,
        _root: &Path,
        _source: Arc<RecordSource>,
    ) -> Result<()> {
        ensure!(
            index.notifications.is_empty(),
            "recorded notifications require an installed native notification capability"
        );
        Ok(())
    }
    fn register(&mut self, phase: Phase, item: <Records as GlobalProjection>::Item) -> Result<()> {
        let (record, reference, row_shape) = item;
        let source_kind = self.source_kind;
        let Self {
            path,
            mysql: _,

            targets,
            identities,
            rules,
            native,
            sql,
            ..
        } = self;
        match phase {
            Phase::Metadata => match record {
                DependencyRecord::MysqlConnection(connection) => {
                    if let Some(identity) = identity_from_connection(&connection) {
                        register_replay_target(targets, &identity.target, ReplayProtocol::Mysql)?;
                        identities.insert(connection.id, identity);
                    }
                }
                DependencyRecord::MysqlExchange(mut exchange) => {
                    let line = reference.location.line;
                    exchange.response.detach(reference);
                    exchange.response.row_shape = row_shape.or(exchange.response.row_shape);
                    sql.push((line, DependencyRecord::MysqlExchange(exchange)));
                }
                DependencyRecord::ProxyError(error) => {
                    ensure!(
                        error.protocol != "redis",
                        "unsafe Redis capture proxy error"
                    );
                    reject_retired_proxy_error(&error)?;
                }
                _ => {}
            },
            Phase::Exchanges => match record {
                DependencyRecord::Native(record) => {
                    validate_installed_provider(&record, &native.providers)?;
                    native.register(
                        &record,
                        source_kind,
                        None,
                        reference.location.line,
                        targets,
                        &crate::request_headers::SourceSecrets::new(path),
                    )?;
                }
                _ => {}
            },
        }
        Ok(())
    }
    fn complete(&mut self, phase: Phase) -> Result<()> {
        match phase {
            Phase::Metadata => Ok(()),
            Phase::Exchanges => register_dependency_records(
                self.path,
                std::mem::take(&mut self.sql),
                &BTreeSet::new(),
                self.source_kind,
                None,
                self.mysql,
                self.targets,
                self.identities,
                self.rules,
                &BTreeSet::new(),
                self.native,
            ),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn load(
    path: &Path,
    source_kind: ReplaySource,
    mysql: &mut MysqlReplayState,

    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    identities: &mut HashMap<Uuid, MysqlDependencyIdentity>,
    rules: &[crate::BackgroundDependencyRuleConfig],
    reader: Arc<std::sync::Mutex<RecordReader>>,
    native: &mut native::Inventory,
) -> Result<()> {
    if source_kind == ReplaySource::Unattributed {
        let path = path.to_owned();
        let (index, _) = tokio::task::spawn_blocking(move || {
            crate::dependency_index::global::load_global_index(&path, validate_index_record)
        })
        .await
        .context("ambient Source index preparation failed")??;
        ensure!(
            index.notifications.is_empty(),
            "recorded notifications require an installed native notification capability"
        );
        return Ok(());
    }
    replay::global::load(
        path,
        reader,
        &mut Registration {
            path,
            source_kind,
            mysql,

            targets,
            identities,
            rules,
            native,
            sql: Vec::new(),
        },
    )
    .await
}
