//! Prepared membership for read-only projections; execution validates recorded cases separately.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Result, ensure};

use super::index::{IndexPathStorage, read_index, validate_index_origin};

/// Read published group membership without discovering or opening recording cases.
/// This snapshot cannot authorize Replay or an evidence revision.
pub(crate) fn load_prepared_case_ids(
    output: &Path,
    case_source: &Path,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let output = fs::canonicalize(output)?;
    let case_source = fs::canonicalize(case_source)?;
    let index = read_index(&output)?;
    let storage = IndexPathStorage::for_index(&index, &case_source)?;
    validate_index_origin(&index, &storage, &output, &case_source)?;
    let mut groups = BTreeMap::new();
    let mut selected_ids = BTreeSet::new();
    for group in index.groups {
        let mut ids = BTreeSet::new();
        for id in group.case_ids {
            ensure!(
                selected_ids.insert(id.clone()),
                "case id {id} belongs to overlapping groups"
            );
            ids.insert(id);
        }
        ensure!(
            groups.insert(group.group_id.clone(), ids).is_none(),
            "duplicate group id {}",
            group.group_id
        );
    }
    Ok(groups)
}
