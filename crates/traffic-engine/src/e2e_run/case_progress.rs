pub(super) fn log_start(total_cases: usize) {
    log_progress(0, total_cases);
}

pub(super) fn log_completion(completed_cases: usize, total_cases: usize) {
    if should_log_completion(completed_cases, total_cases) {
        log_progress(completed_cases, total_cases);
    }
}

fn should_log_completion(completed_cases: usize, total_cases: usize) -> bool {
    if completed_cases == 0 || total_cases == 0 || completed_cases > total_cases {
        return false;
    }
    let current_bucket = completed_cases.saturating_mul(20) / total_cases;
    let previous_bucket = completed_cases.saturating_sub(1).saturating_mul(20) / total_cases;
    current_bucket > previous_bucket
}

fn log_progress(completed_cases: usize, total_cases: usize) {
    let progress_percent = completed_cases
        .saturating_mul(100)
        .checked_div(total_cases)
        .unwrap_or_default();
    tracing::info!(
        completed_cases,
        total_cases,
        progress_percent,
        "E2E case execution progress"
    );
}

#[cfg(test)]
mod tests {
    use super::should_log_completion;

    #[test]
    fn reports_about_every_five_percent_for_large_runs() {
        let total = 296;
        let reported = (1..=total)
            .filter(|completed| should_log_completion(*completed, total))
            .collect::<Vec<_>>();

        assert_eq!(reported.len(), 20);
        assert_eq!(reported.first(), Some(&15));
        assert_eq!(reported.last(), Some(&296));
        assert_eq!(
            reported
                .iter()
                .map(|completed| completed * 20 / total)
                .collect::<Vec<_>>(),
            (1..=20).collect::<Vec<_>>()
        );
    }

    #[test]
    fn reports_every_completion_for_small_groups() {
        assert_eq!(
            (1..=3)
                .filter(|completed| should_log_completion(*completed, 3))
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn ignores_invalid_completion_counts() {
        assert!(!should_log_completion(0, 3));
        assert!(!should_log_completion(1, 0));
        assert!(!should_log_completion(4, 3));
    }
}
