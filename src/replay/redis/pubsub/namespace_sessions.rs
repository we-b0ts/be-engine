//! Namespace identity requires both original protocol metadata and a live peer receipt.
//! The input executor receives no Source response or expected business payload.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::replay::ReplayCase;
mod source;

#[derive(Debug, Default)]
pub(in crate::replay) struct NamespaceSessions {
    source: BTreeMap<String, BTreeMap<String, String>>,
    live: Option<Live>,
}

#[derive(Debug)]
struct Live {
    case: String,
    epoch: DateTime<Utc>,
    observing: bool,
    closed: bool,
    namespaces: BTreeMap<String, String>,
}

impl NamespaceSessions {
    pub(in crate::replay) fn prepare(
        &mut self,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<()> {
        self.source = source::load(cases)?;
        Ok(())
    }

    pub(in crate::replay) fn needs_observer(&self, case: &str) -> bool {
        self.source.contains_key(case)
    }

    pub(in crate::replay) fn epoch(&self, case: &str) -> Option<DateTime<Utc>> {
        self.live
            .as_ref()
            .filter(|live| live.case == case)
            .map(|live| live.epoch)
    }

    pub(in crate::replay) fn begin_case(&mut self) {
        self.live = None;
    }

    pub(in crate::replay) fn request_begin(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
    ) -> Result<()> {
        if !self.needs_observer(case) {
            return Ok(());
        }
        ensure!(
            self.live.is_none(),
            "namespace session request already admitted"
        );
        self.live = Some(Live {
            case: case.into(),
            epoch,
            observing: false,
            closed: false,
            namespaces: BTreeMap::new(),
        });
        Ok(())
    }

    pub(in crate::replay) fn observe_begin(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
    ) -> Result<()> {
        if !self.needs_observer(case) {
            return Ok(());
        }
        let live = self
            .live
            .as_mut()
            .filter(|live| live.case == case)
            .context("namespace session request not admitted")?;
        ensure!(
            live.epoch == epoch && !live.closed,
            "namespace session observer epoch changed"
        );
        live.observing = true;
        Ok(())
    }

    pub(in crate::replay) fn connected(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        namespace: &str,
        sid: Option<&str>,
    ) -> Result<()> {
        let Some(source) = self.source.get(case) else {
            return Ok(());
        };
        let live = self
            .live
            .as_mut()
            .filter(|live| live.case == case)
            .context("namespace session observer not admitted")?;
        ensure!(
            live.observing && !live.closed && live.epoch == epoch,
            "namespace session connection epoch changed"
        );
        ensure!(
            valid_identity(namespace),
            "invalid native namespace metadata"
        );
        if !source.contains_key(namespace) {
            return Ok(());
        }
        let Some(sid) = sid else { return Ok(()) };
        ensure!(
            valid_identity(sid),
            "invalid native namespace session identity"
        );
        if let Some(previous) = live.namespaces.get(namespace) {
            ensure!(previous == sid, "native namespace session identity changed");
        } else {
            live.namespaces.insert(namespace.into(), sid.into());
        }
        Ok(())
    }

    pub(in crate::replay) fn close_case(&mut self, case: &str) {
        if let Some(live) = self.live.as_mut().filter(|live| live.case == case) {
            live.closed = true;
        }
    }

    pub(super) fn matches_room(
        &self,
        case: Option<&str>,
        namespace: &Value,
        source: &Value,
        target: &Value,
    ) -> bool {
        let Some((case, namespace, source, target)) = case
            .zip(namespace.as_str())
            .zip(source.as_str())
            .zip(target.as_str())
            .map(|(((case, namespace), source), target)| (case, namespace, source, target))
        else {
            return false;
        };
        self.source
            .get(case)
            .and_then(|sessions| sessions.get(namespace))
            .is_some_and(|sid| sid == source)
            && self.live.as_ref().is_some_and(|live| {
                live.case == case
                    && live.observing
                    && !live.closed
                    && live
                        .namespaces
                        .get(namespace)
                        .is_some_and(|sid| sid == target)
            })
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests;
