//! Execution failure is independent of the primary service's HTTP status.
use super::model::{ActiveRunState, CaseExecution};
use serde_json::{Value, json};

const PAGE_SIZE: usize = 8;

pub(super) fn record(case: &mut CaseExecution, status: Value, result: &anyhow::Result<Vec<u8>>) {
    if status["failed"] != true {
        return;
    }
    let observed_status = result
        .as_ref()
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .and_then(|response| response["status"].as_u64())
        .or_else(|| {
            result
                .as_ref()
                .err()?
                .downcast_ref::<crate::dependency::execution::UnmatchedDependency>()?
                .observed_status
                .map(u64::from)
        });
    let kind = status["kind"].as_str().unwrap_or("dependency_unmatched");
    let mut failure = json!({"kind":kind,"request_completed":false,"case_id":case.case_id,"failures":status["failures"]});
    if let Some(status) = observed_status {
        failure["observed_primary_status"] = status.into();
    }
    case.execution_failure = Some(failure);
}

pub(super) fn diagnosis(state: &ActiveRunState) -> Vec<Value> {
    state
        .cases
        .iter()
        .filter_map(|case| case.execution_failure.clone())
        .take(PAGE_SIZE)
        .collect()
}

pub(super) fn summary(state: &ActiveRunState) -> Value {
    let total = state
        .cases
        .iter()
        .filter(|case| case.execution_failure.is_some())
        .count();
    json!({"total":total,"returned":total.min(PAGE_SIZE),"omitted":total.saturating_sub(PAGE_SIZE),"page_size":PAGE_SIZE})
}

pub(super) fn page(state: &ActiveRunState, offset: usize) -> anyhow::Result<Value> {
    page_cases(&state.cases, offset)
}

fn page_cases(cases: &[CaseExecution], offset: usize) -> anyhow::Result<Value> {
    let total = cases
        .iter()
        .filter(|case| case.execution_failure.is_some())
        .count();
    anyhow::ensure!(
        offset.is_multiple_of(PAGE_SIZE) && offset <= total,
        "execution failure page offset is outside this attempt or not a page boundary"
    );
    let rows = cases
        .iter()
        .filter_map(|case| case.execution_failure.clone())
        .skip(offset)
        .take(PAGE_SIZE)
        .collect::<Vec<_>>();
    let end = offset + rows.len();
    Ok(json!({"execution_failures":rows,"pagination":{
        "total":total,"offset":offset,"limit":PAGE_SIZE,"returned":rows.len(),
        "omitted":total-rows.len(),"remaining":total-end,
        "next_offset":(end<total).then_some(end)
    }}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_pages_cover_omitted_cases_without_including_successful_or_dirty_only_cases() {
        let cases = (0..19)
            .map(|index| {
                serde_json::from_value(json!({"case_id":format!("case-{index}"),"case_dir":"/cases",
                "group_id":"group","status":"failed","assertion_passed":null,"replay_clean":false,
                "execution_failure":(index%5!=0).then(||json!({"case_id":format!("case-{index}"),
                    "failures":[{"protocol":"redis","command":"GET","target_event_index":index}]}))
            })).unwrap()
            })
            .collect::<Vec<_>>();
        let a = page_cases(&cases, 0).unwrap();
        let b = page_cases(&cases, 8).unwrap();
        assert_eq!(a["pagination"]["total"], 15);
        assert_eq!(a["pagination"]["returned"], 8);
        assert_eq!(a["pagination"]["omitted"], 7);
        assert_eq!(a["pagination"]["next_offset"], 8);
        assert_eq!(b["pagination"]["remaining"], 0);
        assert_eq!(b["pagination"]["next_offset"], Value::Null);
        let rows = a["execution_failures"]
            .as_array()
            .unwrap()
            .iter()
            .chain(b["execution_failures"].as_array().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 15);
        assert_eq!(rows.last().unwrap()["case_id"], "case-18");
        assert!(page_cases(&cases, 1).is_err());
        assert!(page_cases(&cases, 16).is_err());
        assert_eq!(page_cases(&[], 0).unwrap()["pagination"]["total"], 0);
    }
}
