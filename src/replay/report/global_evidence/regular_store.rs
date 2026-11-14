//! Immutable, ordered protocol report projections. Only a cold cache build
//! traverses the full admitted Global inventory.
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::artifact::{ArtifactReference, digest};
use super::regular_usage::Position;
use crate::dependency_index::store;

const VERSION: u32 = 1;
const PAGE_RECORDS: usize = 256;
const PAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub source_sha256: String,
    pub source_bytes: u64,
    pub policy: String,
    pub protocol: String,
    pub layout: Vec<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<String>,
}

impl Identity {
    pub(super) fn key(&self) -> Result<String> {
        digest(&(
            "global-regular-projection",
            VERSION,
            "global-before-case-v1",
            self,
        ))
    }
}

pub(in crate::replay) use traffic_replay::report::Row;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    pub first: Position,
    pub last: Position,
    pub count: usize,
    pub visible: usize,
    pub visible_before: usize,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    version: u32,
    pub identity: Identity,
    pub recorded: usize,
    pub visible: usize,
    pub pages: Vec<Page>,
}

impl Inventory {
    pub(super) fn validate(&self, reference: &ArtifactReference) -> Result<()> {
        ensure!(
            self.version == VERSION && self.identity.key()? == reference.key(),
            "Global projection identity changed"
        );
        let mut recorded = 0usize;
        let mut visible = 0usize;
        let mut previous = None;
        for page in &self.pages {
            ensure!(
                page.first.section == page.last.section
                    && self
                        .identity
                        .layout
                        .get(page.last.section as usize)
                        .is_some_and(|boundary| page.last.index < *boundary),
                "Global projection page exceeds its immutable layout"
            );
            ensure!(
                page.count > 0
                    && page.count <= PAGE_RECORDS
                    && page.visible <= page.count
                    && page.first <= page.last
                    && previous.is_none_or(|last| last < page.first)
                    && page.visible_before == visible,
                "invalid Global projection page order or counts"
            );
            recorded = recorded
                .checked_add(page.count)
                .context("Global projection count overflow")?;
            visible = visible
                .checked_add(page.visible)
                .context("Global projection count overflow")?;
            previous = Some(page.last);
        }
        ensure!(
            recorded == self.recorded && visible == self.visible,
            "Global projection totals changed"
        );
        Ok(())
    }

    pub(super) fn read_page(&self, root: &Path, page: usize) -> Result<Vec<Row>> {
        let expected = self
            .pages
            .get(page)
            .context("Global projection page out of bounds")?;
        let rows: Vec<Row> = store::read_json(&root.join(format!("{page}.json")))?;
        ensure!(
            rows.len() == expected.count
                && rows.first().map(|row| row.position) == Some(expected.first)
                && rows.last().map(|row| row.position) == Some(expected.last)
                && rows
                    .windows(2)
                    .all(|pair| pair[0].position < pair[1].position)
                && rows.iter().filter(|row| row.visible).count() == expected.visible
                && digest(&rows)? == expected.sha256,
            "Global projection page changed"
        );
        Ok(rows)
    }

    pub(super) fn page_for_position(&self, position: Position) -> Result<usize> {
        let page = self.pages.partition_point(|page| page.last < position);
        ensure!(
            self.pages
                .get(page)
                .is_some_and(|page| page.first <= position),
            "Global visibility change is outside its inventory"
        );
        Ok(page)
    }

    pub(super) fn stage(&self, source: &Path, staging: &Path) -> Result<Self> {
        for page in 0..self.pages.len() {
            let from = source.join(format!("{page}.json"));
            let metadata = fs::symlink_metadata(&from)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "linked Global projection page"
            );
            let to = staging.join(format!("{page}.json"));
            if let Err(error) = fs::hard_link(&from, &to) {
                if error.raw_os_error() != Some(libc::EXDEV) {
                    return Err(error.into());
                }
                fs::copy(&from, &to)?;
                fs::File::open(&to)?.sync_all()?;
            }
        }
        Ok(self.clone())
    }
}

pub(super) struct Builder<'a> {
    root: &'a Path,
    inventory: Inventory,
    rows: Vec<Row>,
    bytes: usize,
    previous: Option<Position>,
}

impl<'a> Builder<'a> {
    pub(super) fn new(root: &'a Path, identity: Identity) -> Self {
        Self {
            root,
            inventory: Inventory {
                version: VERSION,
                identity,
                recorded: 0,
                visible: 0,
                pages: vec![],
            },
            rows: vec![],
            bytes: 0,
            previous: None,
        }
    }

    pub(super) fn push(&mut self, row: Row) -> Result<()> {
        ensure!(
            self.previous.is_none_or(|position| position < row.position),
            "Global projection source order changed"
        );
        if self
            .previous
            .is_some_and(|previous| previous.section != row.position.section)
        {
            self.flush()?;
        }
        self.previous = Some(row.position);
        self.bytes = self
            .bytes
            .checked_add(serde_json::to_vec(&row)?.len())
            .context("Global projection page size overflow")?;
        self.rows.push(row);
        if self.rows.len() >= PAGE_RECORDS || self.bytes >= PAGE_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let page = Page {
            first: self.rows.first().unwrap().position,
            last: self.rows.last().unwrap().position,
            count: self.rows.len(),
            visible: self.rows.iter().filter(|row| row.visible).count(),
            visible_before: self.inventory.visible,
            sha256: digest(&self.rows)?,
        };
        store::write_json(
            &self
                .root
                .join(format!("{}.json", self.inventory.pages.len())),
            &self.rows,
        )?;
        self.inventory.recorded += page.count;
        self.inventory.visible += page.visible;
        self.inventory.pages.push(page);
        self.rows.clear();
        self.bytes = 0;
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<Inventory> {
        self.flush()?;
        Ok(self.inventory)
    }
}
