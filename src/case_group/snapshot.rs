//! Prepared membership for read-only projections; execution validates recorded cases separately.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Result, ensure};

use super::index::{IndexPathStorage, read_index, validate_index_origin};

/// Published case identities and fingerprint for one prepared API group.
pub(crate) struct PreparedGroupMembership {
    pub(crate) case_inventory_id: String,
    pub(crate) case_ids: BTreeSet<String>,
}

/// Read published membership without discovering or opening recording cases.
/// This snapshot cannot authorize Replay or an evidence revision.
pub(crate) fn load_prepared_membership(
    output: &Path,
    case_source: &Path,
) -> Result<BTreeMap<String, PreparedGroupMembership>> {
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
            groups
                .insert(
                    group.group_id.clone(),
                    PreparedGroupMembership {
                        case_inventory_id: group.case_inventory_id,
                        case_ids: ids,
                    }
                )
                .is_none(),
            "duplicate group id {}",
            group.group_id
        );
    }
    Ok(groups)
}
