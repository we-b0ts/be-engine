//! Apply declared finite ownership before the new recording becomes immutable.
use super::*;
use crate::source_ownership::{Assignment, CaseFacts, Outcome};
use anyhow::ensure;
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
use std::collections::BTreeSet;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

const RECEIPT: &str = "dependency-ownership.json";

#[derive(Serialize)]
struct OwnershipReceipt {
    schema: &'static str,
    capture_policy_identity: String,
    async_policy_fingerprint: String,
    original_ledger: LedgerFileIdentity,
    assignments: Vec<OwnershipChange>,
    unresolved: Vec<UnresolvedChange>,
    problems: Vec<crate::source_ownership::Problem>,
    limitations: [&'static str; 2],
}

#[derive(Serialize)]
struct OwnershipChange {
    exchange_id: Uuid,
    effect_index: u32,
    original_capture: Value,
    assignment: Assignment,
}

#[derive(Serialize)]
struct UnresolvedChange {
    exchange_id: Uuid,
    effect_index: u32,
    original_capture: Value,
}

#[derive(Deserialize)]
struct CapturedRecord<'a> {
    #[serde(borrow)]
    capture: &'a RawValue,
}

impl LedgerWriter {
    pub(super) async fn apply_declared_ownership(&mut self) -> Result<()> {
        if !self
            .ownership_rules
            .values()
            .flat_map(|rules| rules.iter())
            .any(|rule| rule.ownership.is_some())
        {
            return Ok(());
        }
        ensure!(
            !self.sealed && !self.root.join(MANIFEST_FILE).try_exists()?,
            "declared ownership cannot rewrite a sealed recording"
        );
        let inputs = self.ownership_inputs().await?;
        let events = self.ownership_events().await?;
        let rules = self.ownership_rules.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            crate::source_ownership::classify(&rules, &inputs, &events).unwrap_or_else(|_| {
                Outcome {
                    unresolved: crate::source_ownership::potential_occurrences(&rules, &events),
                    problems: vec![crate::source_ownership::Problem {
                        exchange_id: None,
                        case_id: None,
                        rule_id: crate::policy::ASYNC_API_ID.into(),
                        reason: "async_ownership_execution_failed".into(),
                    }],
                    ..Default::default()
                }
            })
        })
        .await
        .context("recording Source ownership analysis task failed")?;
        self.publish_ownership(outcome).await
    }

    async fn ownership_inputs(&self) -> Result<Vec<CaseFacts>> {
        let mut inputs = Vec::new();
        for input in self.inputs.values().filter(|input| input.complete) {
            let relative = Path::new(&input.path);
            ensure!(
                !relative.is_absolute()
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "recording ownership input escapes its run"
            );
            let directory = self.root.join(relative);
            let request: Value =
                serde_json::from_slice(&tokio::fs::read(directory.join("request.json")).await?)?;
            let response: Value = serde_json::from_slice(
                &tokio::fs::read(directory.join("expected-response.json")).await?,
            )?;
            let (Some(method), Some(uri), Some(timestamp)) = (
                request["method"].as_str(),
                request["uri"].as_str(),
                request.get("timestamp"),
            ) else {
                continue;
            };
            inputs.push(CaseFacts {
                case_id: input.case_id,
                method: method.into(),
                uri: uri.into(),
                request: crate::replay::native_source_request_body(&request),
                request_unavailable: crate::source_ownership::request_unavailable(&request),
                response: crate::replay::native_source_request_body(&response),
                started_at: serde_json::from_value(timestamp.clone())?,
            });
        }
        Ok(inputs)
    }

    async fn ownership_events(&self) -> Result<Vec<Value>> {
        let mut reader =
            BufReader::new(tokio::fs::File::open(self.root.join("dependencies.jsonl")).await?);
        let mut line = Vec::new();
        let mut events = Vec::new();
        let mut original_hash = Sha256::new();
        let mut original_length = 0;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line).await? == 0 {
                break;
            }
            original_hash.update(&line);
            original_length += line.len() as u64;
            // Borrow carrier fields first. Unrelated HTTP bodies and response
            // streams are never retained by the ownership request projection.
            let fields: BTreeMap<&str, &RawValue> = serde_json::from_slice(&line)?;
            if !fields.get("event_type").is_some_and(|kind| {
                matches!(kind.get(), "\"mysql_exchange\"" | "\"redis_exchange\"")
            }) {
                continue;
            }
            let value = serde_json::from_slice(&line)?;
            if let Some(request) =
                crate::source_ownership::request_view(&value, &self.ownership_rules)
            {
                events.push(request);
            }
        }
        ensure!(
            original_length == self.offset
                && original_hash.finalize() == self.ledger_hash.clone().finalize(),
            "new recording ledger changed before ownership classification"
        );
        Ok(events)
    }

    async fn publish_ownership(&mut self, outcome: Outcome) -> Result<()> {
        let original_ledger = LedgerFileIdentity {
            path: "dependencies.jsonl".into(),
            length: self.offset,
            sha256: format!("{:x}", self.ledger_hash.clone().finalize()),
        };
        let temporary = self
            .root
            .join(format!(".dependencies-ownership-{}.jsonl", Uuid::new_v4()));
        ensure!(
            outcome
                .decisions
                .keys()
                .all(|id| !outcome.unresolved.contains(id)),
            "declared ownership has contradictory resolved and unresolved decisions"
        );
        let result = if outcome.decisions.is_empty() && outcome.unresolved.is_empty() {
            Ok((None, Vec::new(), Vec::new()))
        } else {
            self.rewrite_ownership(&temporary, &outcome.decisions, &outcome.unresolved)
                .await
                .map(|(rebuilt, assignments, unresolved)| (Some(rebuilt), assignments, unresolved))
        };
        let (rebuilt, assignments, unresolved) = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(error);
            }
        };
        let receipt = OwnershipReceipt {
            schema: "traffic-source-ownership/v1",
            capture_policy_identity: self.capture_policy_identity.clone(),
            async_policy_fingerprint: crate::policy_evidence::digest(&serde_json::to_vec(
                &self.ownership_rules,
            )?),
            original_ledger,
            assignments,
            unresolved,
            problems: outcome.problems,
            limitations: [
                "finite_source_ownership_does_not_prove_online_async_completion",
                "source_ownership_does_not_prove_target_replay_consumption",
            ],
        };
        if let Err(error) = write_json(&self.root.join(RECEIPT), &receipt).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        ensure!(
            !self.root.join(MANIFEST_FILE).try_exists()?,
            "recording became sealed during ownership publication"
        );
        if let Some(rebuilt) = rebuilt {
            tokio::fs::rename(&temporary, self.root.join("dependencies.jsonl")).await?;
            rebuilt.install(self);
        }
        Ok(())
    }

    async fn rewrite_ownership(
        &self,
        temporary: &Path,
        decisions: &BTreeMap<Uuid, Assignment>,
        unresolved: &BTreeSet<Uuid>,
    ) -> Result<(RebuiltLedger, Vec<OwnershipChange>, Vec<UnresolvedChange>)> {
        let path = self.root.join("dependencies.jsonl");
        let original = tokio::fs::File::open(&path).await?;
        let output = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temporary)
            .await?;
        output
            .set_permissions(original.metadata().await?.permissions())
            .await?;
        let mut reader = BufReader::new(original);
        let mut writer = BufWriter::new(output);
        let mut rebuilt = RebuiltLedger::default();
        let mut changes = Vec::new();
        let mut unresolved_changes = Vec::new();
        let mut seen = BTreeSet::new();
        let mut line = Vec::new();
        let mut original_hash = Sha256::new();
        let mut original_length = 0;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line).await? == 0 {
                break;
            }
            original_hash.update(&line);
            original_length += line.len() as u64;
            let captured: CapturedRecord<'_> = serde_json::from_slice(&line)?;
            let mut metadata: CaptureMetadata = serde_json::from_str(captured.capture.get())?;
            if let Some(assignment) = decisions.get(&metadata.exchange_id) {
                ensure!(
                    metadata.phase == CapturePhase::Runtime
                        && matches!(
                            metadata.attribution,
                            DependencyOwner::Case { .. } | DependencyOwner::Unattributed { .. }
                        )
                        && self
                            .inputs
                            .get(&assignment.case_id)
                            .is_some_and(|input| input.complete),
                    "declared ownership leaves its complete runtime Case scope"
                );
                let original_capture: Value = serde_json::from_str(captured.capture.get())?;
                metadata.attribution = DependencyOwner::Case {
                    origin_case_id: assignment.case_id,
                    task_instance: None,
                };
                if metadata.matched_rule_id.is_none() {
                    metadata.matched_rule_id = Some(assignment.rule_id.clone());
                }
                if !metadata.matched_rule_ids.contains(&assignment.rule_id) {
                    metadata.matched_rule_ids.push(assignment.rule_id.clone());
                }
                let mut effective_capture = original_capture.clone();
                effective_capture["attribution"] = serde_json::to_value(&metadata.attribution)?;
                effective_capture["matched_rule_id"] =
                    serde_json::to_value(&metadata.matched_rule_id)?;
                effective_capture["matched_rule_ids"] =
                    serde_json::to_value(&metadata.matched_rule_ids)?;
                line = replace_capture(&line, captured.capture, &effective_capture)?;
                seen.insert(metadata.exchange_id);
                changes.push(OwnershipChange {
                    exchange_id: metadata.exchange_id,
                    effect_index: metadata.effect_index,
                    original_capture,
                    assignment: assignment.clone(),
                });
            } else if unresolved.contains(&metadata.exchange_id) {
                ensure!(
                    metadata.phase == CapturePhase::Runtime
                        && matches!(
                            metadata.attribution,
                            DependencyOwner::Case { .. } | DependencyOwner::Unattributed { .. }
                        ),
                    "unresolved async ownership leaves its runtime Case scope"
                );
                let original_capture: Value = serde_json::from_str(captured.capture.get())?;
                metadata.attribution = DependencyOwner::Unattributed {
                    reason: "declared_async_ownership_unresolved".into(),
                };
                let mut effective_capture = original_capture.clone();
                effective_capture["attribution"] = serde_json::to_value(&metadata.attribution)?;
                line = replace_capture(&line, captured.capture, &effective_capture)?;
                seen.insert(metadata.exchange_id);
                unresolved_changes.push(UnresolvedChange {
                    exchange_id: metadata.exchange_id,
                    effect_index: metadata.effect_index,
                    original_capture,
                });
            }
            rebuilt.observe(&line, &metadata)?;
            writer.write_all(&line).await?;
        }
        ensure!(
            seen.len() == decisions.len() + unresolved.len(),
            "declared ownership references an absent original dependency"
        );
        ensure!(
            rebuilt.records == self.records,
            "declared ownership changes physical recording cardinality"
        );
        ensure!(
            original_length == self.offset
                && original_hash.finalize() == self.ledger_hash.clone().finalize(),
            "new recording ledger changed during ownership publication"
        );
        writer.flush().await?;
        crate::recorder::storage::flush_and_evict(writer.get_mut(), 0).await?;
        Ok((rebuilt, changes, unresolved_changes))
    }
}

fn replace_capture(line: &[u8], raw: &RawValue, effective: &Value) -> Result<Vec<u8>> {
    let start = (raw.get().as_ptr() as usize)
        .checked_sub(line.as_ptr() as usize)
        .context("ownership capture token precedes its carrier")?;
    let end = start
        .checked_add(raw.get().len())
        .context("capture token overflow")?;
    ensure!(
        line.get(start..end) == Some(raw.get().as_bytes()),
        "ownership capture token leaves its original carrier"
    );
    let mut output = Vec::with_capacity(line.len());
    output.extend_from_slice(&line[..start]);
    output.extend_from_slice(&serde_json::to_vec(effective)?);
    output.extend_from_slice(&line[end..]);
    Ok(output)
}

#[derive(Default)]
struct RebuiltLedger {
    offset: u64,
    records: usize,
    unattributed: u64,
    ledger_hash: Sha256,
    cases: BTreeMap<Uuid, Vec<ScopeRecordLocation>>,
    startup: Vec<ScopeRecordLocation>,
    process: Vec<ScopeRecordLocation>,
    shutdown: Vec<ScopeRecordLocation>,
    unknown: Vec<ScopeRecordLocation>,
    semantic_inventory: SemanticInventory,
}

impl RebuiltLedger {
    fn observe(&mut self, line: &[u8], metadata: &CaptureMetadata) -> Result<()> {
        let location = ScopeRecordLocation {
            line: self.records + 1,
            offset: self.offset,
            length: line.len() as u64,
            sha256: format!("{:x}", Sha256::digest(line)),
            exchange_id: metadata.exchange_id,
            effect_index: metadata.effect_index,
        };
        self.offset += line.len() as u64;
        self.records += 1;
        self.ledger_hash.update(line);
        if metadata.semantic_required {
            let value = serde_json::from_slice(line)?;
            self.semantic_inventory
                .observe_mandatory(&value, &metadata.attribution);
        }
        match metadata.attribution {
            DependencyOwner::Case { origin_case_id, .. } => {
                self.cases.entry(origin_case_id).or_default().push(location);
            }
            DependencyOwner::Startup { .. } => self.startup.push(location),
            DependencyOwner::Process { .. } => self.process.push(location),
            DependencyOwner::Shutdown { .. } => self.shutdown.push(location),
            DependencyOwner::Unattributed { .. } => {
                self.unattributed += 1;
                self.unknown.push(location);
            }
        }
        Ok(())
    }

    fn install(self, ledger: &mut LedgerWriter) {
        ledger.offset = self.offset;
        ledger.records = self.records;
        ledger.unattributed = self.unattributed;
        ledger.ledger_hash = self.ledger_hash;
        ledger.cases = self.cases;
        ledger.startup = self.startup;
        ledger.process = self.process;
        ledger.shutdown = self.shutdown;
        ledger.unknown = self.unknown;
        ledger.semantic_inventory = self.semantic_inventory;
    }
}

#[cfg(test)]
#[path = "ownership/tests.rs"]
mod tests;
