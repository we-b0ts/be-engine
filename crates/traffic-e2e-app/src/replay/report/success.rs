use std::collections::BTreeMap;

pub(crate) const SUCCESS_DETAIL_LIMIT: usize = 100;
pub(crate) const SUCCESS_DETAIL_SCOPE: &str = "case";

#[derive(Debug, Default)]
pub(crate) struct SuccessDetailBudget {
    observed_by_case: BTreeMap<Option<String>, usize>,
}

impl SuccessDetailBudget {
    pub(crate) fn next_event_index(&self, case_id: Option<&str>) -> usize {
        self.observed_by_case
            .get(&case_id.map(ToOwned::to_owned))
            .copied()
            .unwrap_or_default()
    }
}

pub(crate) fn push_success_detail<T, F>(
    total: &mut usize,
    details: &mut Vec<T>,
    budget: &mut SuccessDetailBudget,
    case_id: Option<&str>,
    detail: F,
) where
    F: FnOnce(usize) -> T,
{
    *total += 1;
    let observed = budget
        .observed_by_case
        .entry(case_id.map(ToOwned::to_owned))
        .or_default();
    let case_event_index = *observed;
    *observed += 1;
    if case_event_index < SUCCESS_DETAIL_LIMIT {
        details.push(detail(case_event_index));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_a_bounded_prefix_per_case_while_counting_every_success() {
        let mut total = 0;
        let mut details = Vec::new();
        let mut budget = SuccessDetailBudget::default();
        for value in 0..(SUCCESS_DETAIL_LIMIT + 7) {
            push_success_detail(
                &mut total,
                &mut details,
                &mut budget,
                Some("case-a"),
                |_| ("case-a", value),
            );
        }
        for value in 0..7 {
            push_success_detail(
                &mut total,
                &mut details,
                &mut budget,
                Some("case-b"),
                |index| {
                    assert_eq!(index, value);
                    ("case-b", value)
                },
            );
        }
        assert_eq!(total, SUCCESS_DETAIL_LIMIT + 14);
        assert_eq!(details.len(), SUCCESS_DETAIL_LIMIT + 7);
        assert_eq!(details[0], ("case-a", 0));
        assert_eq!(
            details[SUCCESS_DETAIL_LIMIT - 1],
            ("case-a", SUCCESS_DETAIL_LIMIT - 1)
        );
        assert_eq!(details[SUCCESS_DETAIL_LIMIT], ("case-b", 0));
    }
}
