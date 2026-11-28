//! Sequential protocol dispositions proved from facts collected by the recorder.
use std::{
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use traffic_model::recording::LedgerFileIdentity;
pub use traffic_protocol::connection::SessionDecision;

use crate::{session_integrity, source::recording, writer::FileDigest};

pub const FILE: &str = "session-schedule.jsonl";
pub const INDEX: &str = "session-schedule-checksums.bin";

pub async fn seal(
    root: &Path,
    mut decisions: Vec<SessionDecision>,
) -> Result<[LedgerFileIdentity; 2]> {
    decisions.sort_unstable_by_key(|decision| decision.sequence);
    let mut bytes = Vec::new();
    let mut previous = 0;
    for decision in &decisions {
        validate(decision, previous)?;
        serde_json::to_writer(&mut bytes, decision)?;
        bytes.push(b'\n');
        previous = decision.sequence;
    }
    crate::storage::write(&root.join(FILE), &bytes).await?;
    let mut chunks = session_integrity::Chunks::default();
    chunks.observe(&bytes);
    let mut digest = FileDigest::default();
    digest.observe(&bytes);
    let mut identity = digest.identity(FILE);
    let index = chunks.seal(root, INDEX, &mut identity).await?;
    Ok([identity, index])
}

pub fn read(root: &Path) -> Result<impl Iterator<Item = Result<SessionDecision>> + Send + use<>> {
    let (root, manifest) = recording::manifest(root)?;
    let input = session_integrity::open(&root, &manifest, FILE, INDEX)?;
    let mut input = BufReader::new(input);
    let mut row = Vec::new();
    let mut previous = 0;
    let mut done = false;
    Ok(std::iter::from_fn(move || {
        if done {
            return None;
        }
        let decision = (|| {
            row.clear();
            if input.read_until(b'\n', &mut row)? == 0 {
                return Ok(None);
            }
            let decision: SessionDecision =
                serde_json::from_slice(&row).context("decode Session schedule")?;
            validate(&decision, previous)?;
            previous = decision.sequence;
            Ok(Some(decision))
        })();
        done = !matches!(decision, Ok(Some(_)));
        decision.transpose()
    }))
}

fn validate(decision: &SessionDecision, previous: u64) -> Result<()> {
    ensure!(
        decision.sequence > previous,
        "duplicate or unordered Session schedule sequence {}",
        decision.sequence
    );
    ensure!(
        decision.step.is_some() != decision.driver_prelude.is_some(),
        "invalid Session schedule disposition at sequence {}",
        decision.sequence
    );
    Ok(())
}
