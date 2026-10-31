//! Source transactions which start in Global retain that owner across Case files.
//! Preparation reads immutable evidence once; request matching uses compact wire keys.
use super::*;
use crate::dependency_index::{
    FileStamp, RecordLocation, RecordReader, RecordSource,
    mysql_transactions::{self, Facts, Member as FactMember},
    store,
};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex as StdMutex},
};

mod cache;
#[cfg(test)]
mod tests;
mod validation;

const MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Default)]
pub(in crate::replay) struct Prepared {
    pub promoted: Vec<PromotedRecord>,
    pub wires: HashSet<(Uuid, u64)>,
    pub cache_reused: bool,
    pub source_bytes: u64,
}

#[derive(Debug)]
pub(in crate::replay) struct PromotedRecord {
    pub source: ReplaySource,
    pub record: RecordedMysqlExchange,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::replay) struct Provenance {
    pub source_owner_kind: String,
    pub original_case_id: String,
    pub dependencies_path: PathBuf,
    pub line: usize,
    pub record_sha256: String,
    pub start_connection_id: Uuid,
    pub start_query_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Proof {
    owner_kind: RunOwnerKind,
    connection: Uuid,
    start_sequence: u64,
    members: Vec<Locator>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunOwnerKind {
    Startup,
    Process,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Locator {
    file: PathBuf,
    location: RecordLocation,
    sequence: u64,
}

/// This is deliberately separate from configured API-origin ownership. A Global
/// transaction needs no API trigger, and every original Case locator is retained.
pub(in crate::replay) fn prepare(source: &Path) -> Result<Prepared> {
    // Central scopes already carry independently frozen owners. Never let an
    // unindexed legacy sidecar promote Case obligations out of those scopes.
    if crate::dependency_index::recording::root(source).is_some() {
        return Ok(Prepared::default());
    }
    if !source
        .ancestors()
        .any(|path| path.join("recording-run.json").is_file())
    {
        return Ok(Prepared::default());
    }
    let (root, cases) = store::recording_files(source)?;
    if !root.join("global-dependencies.jsonl").try_exists()? {
        return Ok(Prepared::default());
    }
    let directory = store::cache_directory(&root);
    store::private_directory(&directory)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("mysql-global-transaction-proof.lock"))?;
    lock.lock()?;
    let output = directory.join("mysql-global-transaction-proof-v2.json");
    let reader = Arc::new(StdMutex::new(RecordReader::new(8 * 1024 * 1024)));
    let mut loaded = BTreeMap::new();
    let (binding, proofs, cache_reused) =
        if let Some((binding, proofs)) = cache::load(&output, &root, &cases)? {
            (binding, proofs, true)
        } else {
            let facts = mysql_transactions::load(&root, &cases)?;
            let binding = cache::Binding::read(&root, &facts)?;
            let proofs = prove(&root, &facts, &binding, &reader, &mut loaded)?;
            binding.validate(&root)?;
            cache::save(&output, &binding, &proofs)?;
            (binding, proofs, false)
        };
    let mut prepared = project(&root, &binding, &reader, &proofs, &mut loaded)?;
    binding.validate(&root)?;
    prepared.cache_reused = cache_reused;
    prepared.source_bytes = reader
        .lock()
        .map_err(|_| anyhow!("MySQL transaction proof reader lock poisoned"))?
        .source_bytes;
    Ok(prepared)
}

type Reader = Arc<StdMutex<RecordReader>>;
type Loaded = BTreeMap<(PathBuf, usize), RecordedMysqlExchange>;

fn prove(
    root: &Path,
    facts: &Facts,
    binding: &cache::Binding,
    reader: &Reader,
    loaded: &mut Loaded,
) -> Result<Vec<Proof>> {
    let mut proofs = Vec::new();
    let mut sql = validation::SqlKinds::default();
    for transaction in &facts.transactions {
        if !transaction.known_start || !transaction.closed {
            continue;
        }
        let Some(first) = transaction.members.first() else {
            continue;
        };
        if !is_global(facts, first)
            || !transaction.members.iter().any(|m| !is_global(facts, m))
            || transaction.members.iter().any(|member| {
                facts.files[member.file].records[member.record]
                    .location
                    .length
                    > MAX_RECORD_BYTES
            })
        {
            continue;
        }
        let summary = &facts.files[first.file].records[first.record].summary;
        let Some((connection, start_sequence)) = summary["connection_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .zip(summary["query_sequence"].as_u64())
        else {
            continue;
        };
        let mut valid = true;
        let mut owner_kind = None;
        let mut savepoints = crate::mysql::savepoint::Names::default();
        let mut case_records = Vec::new();
        let mut members = Vec::new();
        for (position, member) in transaction.members.iter().enumerate() {
            let file = &facts.files[member.file];
            let entry = &file.records[member.record];
            let locator = Locator {
                file: file.path.clone(),
                location: entry.location.clone(),
                sequence: entry.summary["query_sequence"]
                    .as_u64()
                    .context("Source transaction member has no sequence")?,
            };
            let record = read(root, binding, reader, &locator, connection)?;
            if position == 0 {
                owner_kind = read_owner(root, binding, reader, &locator)?;
                if owner_kind.is_none() {
                    valid = false;
                    break;
                }
            }
            if !validation::member(&record, position, transaction.members.len(), &mut sql)
                || record
                    .sql
                    .as_deref()
                    .and_then(crate::mysql::savepoint::parse)
                    .is_some_and(|command| !savepoints.observe(&command))
            {
                valid = false;
                break;
            }
            if !is_global(facts, member) {
                case_records.push(((locator.file.clone(), locator.location.line), record));
            }
            members.push(locator);
        }
        if !valid {
            continue;
        }
        proofs.push(Proof {
            owner_kind: owner_kind.context("transaction has no independently proven run owner")?,
            connection,
            start_sequence,
            members,
        });
        loaded.extend(case_records);
    }
    Ok(proofs)
}

fn project(
    root: &Path,
    binding: &cache::Binding,
    reader: &Reader,
    proofs: &[Proof],
    loaded: &mut Loaded,
) -> Result<Prepared> {
    let mut prepared = Prepared::default();
    let mut sources = BTreeMap::new();
    for proof in proofs {
        let (owner_source, source_owner_kind) = match proof.owner_kind {
            RunOwnerKind::Startup => (ReplaySource::Startup, "startup"),
            RunOwnerKind::Process => (ReplaySource::Process, "process"),
        };
        for member in &proof.members {
            prepared.wires.insert((proof.connection, member.sequence));
            if member.file == Path::new("global-dependencies.jsonl") {
                continue;
            }
            let path = root.join(&member.file);
            let stamp = binding.stamp(&member.file)?;
            let mut record = match loaded.remove(&(member.file.clone(), member.location.line)) {
                Some(record) => record,
                None => read(root, binding, reader, member, proof.connection)?,
            };
            let source = sources
                .entry(member.file.clone())
                .or_insert_with(|| RecordSource::new(&path, stamp.clone(), reader.clone()));
            // read() has already detached rows and retained their original shape.
            record.response.evidence = Some(source.reference(member.location.clone()));
            prepared.promoted.push(PromotedRecord {
                source: owner_source,
                record,
                provenance: Provenance {
                    source_owner_kind: source_owner_kind.into(),
                    original_case_id: path
                        .parent()
                        .and_then(Path::file_name)
                        .and_then(|name| name.to_str())
                        .context("MySQL transaction Case has no identity")?
                        .to_owned(),
                    dependencies_path: path,
                    line: member.location.line,
                    record_sha256: member.location.sha256.clone(),
                    start_connection_id: proof.connection,
                    start_query_sequence: proof.start_sequence,
                },
            });
        }
    }
    Ok(prepared)
}

fn read_owner(
    root: &Path,
    binding: &cache::Binding,
    reader: &Reader,
    first: &Locator,
) -> Result<Option<RunOwnerKind>> {
    let raw = reader
        .lock()
        .map_err(|_| anyhow!("MySQL transaction proof reader lock poisoned"))?
        .read(
            &root.join(&first.file),
            binding.stamp(&first.file)?,
            &first.location,
        )?;
    let original: Value = serde_json::from_slice(&raw)?;
    // Immutable capture provenance, never the filename or current Target state.
    let Ok(owner) = serde_json::from_value::<crate::dependency::attribution::DependencyOwner>(
        original["capture"]["attribution"].clone(),
    ) else {
        return Ok(None);
    };
    owner.validate()?;
    Ok(match owner {
        crate::dependency::attribution::DependencyOwner::Startup { .. } => {
            Some(RunOwnerKind::Startup)
        }
        crate::dependency::attribution::DependencyOwner::Process { .. } => {
            Some(RunOwnerKind::Process)
        }
        _ => None,
    })
}

fn is_global(facts: &Facts, member: &FactMember) -> bool {
    facts.files[member.file].path == Path::new("global-dependencies.jsonl")
}

fn read(
    root: &Path,
    binding: &cache::Binding,
    reader: &Reader,
    member: &Locator,
    connection: Uuid,
) -> Result<RecordedMysqlExchange> {
    let stamp = binding.stamp(&member.file)?;
    let raw = reader
        .lock()
        .map_err(|_| anyhow!("MySQL transaction proof reader lock poisoned"))?
        .read(&root.join(&member.file), stamp, &member.location)?;
    #[derive(Deserialize)]
    struct Envelope {
        event_type: String,
        #[serde(flatten)]
        exchange: RecordedMysqlExchange,
    }
    let envelope: Envelope = serde_json::from_slice(&raw)?;
    ensure!(
        envelope.event_type == "mysql_exchange",
        "MySQL transaction locator does not identify a MySQL exchange"
    );
    let mut record = envelope.exchange;
    ensure!(
        record.connection_id == Some(connection) && record.query_sequence == Some(member.sequence),
        "MySQL transaction wire identity differs from its Source index"
    );
    record.response.detach(
        RecordSource::new(&root.join(&member.file), stamp.clone(), reader.clone())
            .reference(member.location.clone()),
    );
    Ok(record)
}
