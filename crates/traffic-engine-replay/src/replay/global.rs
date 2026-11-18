//! Bounded Global traversal retains producer lifetime and immutable Source validation.
use super::*;
use crate::dependency_index::global::{GlobalEntry, GlobalIndex};
use crate::dependency_index::{Paged, RecordReader, RecordSource};

#[derive(Debug, Clone, Copy)]
pub enum Phase {
    Metadata,
    Exchanges,
}

impl Phase {
    fn context(self) -> &'static str {
        match self {
            Self::Metadata => "Global metadata traversal failed",
            Self::Exchanges => "Global exchange traversal failed",
        }
    }
}

pub trait GlobalProjection: Send + Sync + 'static {
    type Item: Send + 'static;
    fn validate(record: &Value) -> Result<()>;
    fn accepts(phase: Phase, record: &Value) -> Result<bool>;
    fn decode(entry: GlobalEntry, source: &Arc<RecordSource>) -> Result<Self::Item>;
}

pub trait GlobalRegistrar {
    type Projection: GlobalProjection;
    fn evidence(&self) -> Option<traffic_protocol::evidence::EvidenceRegistry> {
        None
    }
    fn prepare(
        &mut self,
        index: &GlobalIndex,
        root: &Path,
        source: Arc<RecordSource>,
    ) -> Result<()>;
    fn register(
        &mut self,
        phase: Phase,
        item: <Self::Projection as GlobalProjection>::Item,
    ) -> Result<()>;
    fn complete(&mut self, phase: Phase) -> Result<()>;
}

type StreamBatch<P> = Vec<<P as GlobalProjection>::Item>;

pub fn stream<P: GlobalProjection>(
    inventory: Paged<GlobalEntry>,
    source: Arc<RecordSource>,
    phase: Phase,
) -> (
    tokio::sync::mpsc::Receiver<StreamBatch<P>>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::task::spawn_blocking(move || {
        for page in 0..inventory.pages() {
            let mut batch = Vec::new();
            for entry in inventory.read_page(page)? {
                if !P::accepts(phase, &entry.record)? {
                    continue;
                }
                batch.push(P::decode(entry, &source)?);
            }
            // Original pages bound each batch. A single queued batch bounds producer lookahead.
            if !batch.is_empty() && tx.blocking_send(batch).is_err() {
                return Ok(());
            }
        }
        source.validate()?;
        Ok(())
    });
    (rx, task)
}

pub async fn consume<T>(
    mut input: tokio::sync::mpsc::Receiver<Vec<T>>,
    task: tokio::task::JoinHandle<Result<()>>,
    context: &'static str,
    mut register: impl FnMut(T) -> Result<()>,
) -> Result<()> {
    let registration = async {
        while let Some(batch) = input.recv().await {
            for item in batch {
                register(item)?;
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Close the bounded channel before joining when registration fails.
    drop(input);
    let traversal = task.await.context(context);
    registration?;
    traversal??;
    Ok(())
}

pub async fn load<R: GlobalRegistrar>(
    path: &Path,
    reader: Arc<std::sync::Mutex<RecordReader>>,
    registrar: &mut R,
) -> Result<()> {
    let source_path = path.to_owned();
    let evidence = registrar
        .evidence()
        .unwrap_or_else(|| crate::protocols::default_providers().evidence().clone());
    let (index, root) = tokio::task::spawn_blocking(move || {
        crate::dependency_index::global::load_global_index_with_evidence(
            &source_path,
            R::Projection::validate,
            &std::sync::atomic::AtomicBool::new(false),
            &evidence,
        )
    })
    .await
    .context("Global index preparation failed")??;
    let source = RecordSource::new(path, index.stamp.clone(), reader);
    registrar.prepare(&index, &root, source.clone())?;
    let records = crate::dependency_index::global::global_records(&index, &root)?;
    for phase in [Phase::Metadata, Phase::Exchanges] {
        let (input, task) = stream::<R::Projection>(records.clone(), source.clone(), phase);
        consume(input, task, phase.context(), |item| {
            registrar.register(phase, item)
        })
        .await?;
        registrar.complete(phase)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
