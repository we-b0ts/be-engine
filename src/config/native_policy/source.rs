//! Source effects validate immutable acquisition/ownership facts, with their own
//! follow-up obligations. They never turn a one-sided fact into value equality.
mod capture;
mod classification;
mod inventory;
use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub(crate) struct NativeSourceScope<'a> {
    pub target_root: &'a Path,
    pub case_source: &'a Path,
    pub source_revision: &'a str,
    pub recording_run_id: &'a str,
    pub prepared_cases: &'a BTreeMap<String, PathBuf>,
    pub replay_report: &'a Path,
    pub policy_rules: &'a [CompiledNativeRule],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeSourceInventory {
    pub recording_root: PathBuf,
    pub recording_run_id: String,
    pub digest: String,
    pub artifact_paths: BTreeSet<PathBuf>,
    #[serde(default)]
    pub snapshot: crate::dependency_index::evidence::Snapshot,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourceObligation {
    FreshRecording,
    AttributionReview,
    Replay,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct NativeSourceValidation {
    pub rules: BTreeMap<String, usize>,
    pub inventory: NativeSourceInventory,
    pub obligations: BTreeSet<SourceObligation>,
    /// Scope/complete input can be proven before recapture. Built-in plugin
    /// output is an explicit fresh-recording obligation, not a value equality.
    pub pending_effect_evidence: BTreeSet<String>,
}

pub(crate) fn validate_source(
    scope: NativeSourceScope<'_>,
    rules: &[CompiledNativeRule],
) -> Result<NativeSourceValidation> {
    let (mut inventory, files) = inventory::load(&scope)?;
    let mut checked = BTreeMap::new();
    let mut obligations = BTreeSet::new();
    let mut pending_effect_evidence = BTreeSet::new();
    for compiled in rules {
        let rule = &compiled.rule;
        if matches!(&rule.effect, n::NativeEffect::CaptureHttpResponse(effect)
            if !matches!(effect.contract,n::CaptureResponseContract::Urls{..}))
        {
            pending_effect_evidence.insert(rule.id.clone());
        }
        let count = match &rule.effect {
            n::NativeEffect::CaptureHttp(_)
            | n::NativeEffect::CaptureBreeze(_)
            | n::NativeEffect::CaptureHttpResponse(_) => {
                obligations.insert(SourceObligation::FreshRecording);
                capture::validate(&scope, rule, &files, &mut inventory.artifact_paths)?
            }
            n::NativeEffect::ProcessOwned(effect) => {
                obligations.insert(SourceObligation::AttributionReview);
                // Explicit initial loads change bootstrap acquisition. Finite
                // process ownership preserves the original single-use exchanges.
                if matches!(
                    &effect.selector,
                    n::ProcessSelector::Redis {
                        initial_load_timeout_ms: Some(_),
                        ..
                    }
                ) {
                    obligations.insert(SourceObligation::FreshRecording);
                }
                classification::validate(&scope, compiled, &files, &mut inventory.artifact_paths)?
            }
            n::NativeEffect::FiniteSharing(_) => {
                obligations.insert(SourceObligation::Replay);
                crate::replay::validate_native_finite_sharing(
                    scope.case_source,
                    scope.replay_report,
                    compiled,
                )?
            }
            _ => continue,
        };
        checked.insert(rule.id.clone(), count);
    }
    inventory.digest = inventory::digest(&inventory)?;
    Ok(NativeSourceValidation {
        rules: checked,
        inventory,
        obligations,
        pending_effect_evidence,
    })
}

#[derive(Debug, Clone, Copy)]
pub(super) enum SourceEventRole<'a> {
    Case(&'a str),
    Global,
}
impl<'a> SourceEventRole<'a> {
    pub(super) fn case_id(self) -> Option<&'a str> {
        match self {
            Self::Case(case) => Some(case),
            Self::Global => None,
        }
    }
}

pub(super) fn each_event(
    files: &[PathBuf],
    selected: impl Fn(SourceEventRole<'_>, &serde_json::Value) -> Result<bool>,
    mut visitor: impl FnMut(&Path, SourceEventRole<'_>, &serde_json::Value) -> Result<()>,
) -> Result<()> {
    for path in files {
        let case = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .context("Source dependency has no case identity")?;
        let role = || {
            if path
                .file_name()
                .is_some_and(|name| name == "global-dependencies.jsonl")
            {
                SourceEventRole::Global
            } else {
                SourceEventRole::Case(case)
            }
        };
        crate::dependency_index::proof::visit(
            path,
            |event| selected(role(), event),
            |event| visitor(path, role(), event),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
