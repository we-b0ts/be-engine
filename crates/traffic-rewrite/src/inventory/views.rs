//! Route-level public inventory projected from the method-level verification ledger.
use std::collections::BTreeMap;

use super::super::model::{
    RewriteApiInventoryDetails, RewriteApiInventoryItem, RewriteApiInventoryView, RewriteApiStatus,
    RewritePhase, RewriteState,
};

pub(crate) fn view(state: &RewriteState) -> RewriteApiInventoryView {
    summary(state, &items(state))
}

pub(crate) fn details(state: &RewriteState) -> RewriteApiInventoryDetails {
    let items = items(state);
    RewriteApiInventoryDetails {
        summary: summary(state, &items),
        items,
    }
}

fn api_key(api: &str) -> &str {
    super::super::api_selector::public_api(api)
}

fn items(state: &RewriteState) -> Vec<RewriteApiInventoryItem> {
    let mut positions = BTreeMap::new();
    let mut items = Vec::<RewriteApiInventoryItem>::new();
    for (method_index, stored) in state.api_inventory.iter().enumerate() {
        let mut method = stored.clone();
        if method.status != RewriteApiStatus::Skipped
            && method.api == state.api
            && state.phase == RewritePhase::SystemRepairRequired
        {
            method.status = RewriteApiStatus::SystemRepairRequired;
        }
        if state.current_api_index == Some(method_index) {
            method.source_route =
                (!state.source_route.is_empty()).then(|| state.source_route.clone());
            method.attempts = state.attempts.len();
            method.e2e_current = state.e2e_current;
        }
        let api = api_key(&method.api).to_string();
        let position = *positions.entry(api.clone()).or_insert_with(|| {
            let position = items.len();
            items.push(RewriteApiInventoryItem {
                api,
                status: RewriteApiStatus::Skipped,
                methods: Vec::new(),
            });
            position
        });
        let item = &mut items[position];
        if priority(method.status) < priority(item.status) {
            item.status = method.status;
        }
        item.methods.push(method);
    }
    items
}

// A blocking or unfinished method keeps the whole route unfinished. Skipped
// siblings are ignored unless every recorded method on the route is skipped.
fn priority(status: RewriteApiStatus) -> u8 {
    match status {
        RewriteApiStatus::SystemRepairRequired => 0,
        RewriteApiStatus::AwaitingRecordingRefresh => 1,
        RewriteApiStatus::ImplementationRequired => 2,
        RewriteApiStatus::Active => 3,
        RewriteApiStatus::RevalidationPending => 4,
        RewriteApiStatus::Pending => 5,
        RewriteApiStatus::Complete => 6,
        RewriteApiStatus::Skipped => 7,
    }
}

fn summary(state: &RewriteState, items: &[RewriteApiInventoryItem]) -> RewriteApiInventoryView {
    let count = |status| items.iter().filter(|item| item.status == status).count();
    let current_index = state
        .current_api_index
        .and_then(|index| state.api_inventory.get(index))
        .and_then(|method| {
            items
                .iter()
                .position(|item| item.api == api_key(&method.api))
        });
    RewriteApiInventoryView {
        total: items.len(),
        completed: count(RewriteApiStatus::Complete),
        skipped: count(RewriteApiStatus::Skipped),
        pending: count(RewriteApiStatus::Pending),
        active: count(RewriteApiStatus::Active),
        implementation_required: count(RewriteApiStatus::ImplementationRequired),
        system_repair_required: count(RewriteApiStatus::SystemRepairRequired),
        awaiting_recording_refresh: count(RewriteApiStatus::AwaitingRecordingRefresh),
        revalidation_pending: count(RewriteApiStatus::RevalidationPending),
        current_index,
        current_api: current_index.map(|index| items[index].api.clone()),
    }
}

#[cfg(test)]
mod tests;
